using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

Console.WriteLine("Starting EKS Windows Node Bootstrapper");
Console.WriteLine("Gathering system configuration...");
var stopWatch = new Stopwatch();
stopWatch.Start();

var clusterName = Environment.GetEnvironmentVariable("CLUSTER_NAME") ?? throw new ArgumentNullException("CLUSTER_NAME");
var dnsClusterIP = Environment.GetEnvironmentVariable("DNS_CLUSTER_IP") ?? throw new ArgumentNullException("DNS_CLUSTER_IP");
var programFilesDirectory = Environment.GetEnvironmentVariable("ProgramFiles") ?? "C:\\Program Files";
var programDataDirectory = Environment.GetEnvironmentVariable("ProgramData") ?? "C:\\ProgramData";
var apiVersionAuthentication = Environment.GetEnvironmentVariable("API_VERSION_AUTHENTICATION") ?? "client.authentication.k8s.io/v1beta1";
var containerRuntime = Environment.GetEnvironmentVariable("CONTAINER_RUNTIME") ?? "containerd";
var eksPauseImage = Environment.GetEnvironmentVariable("EKS_PAUSE_IMAGE") ?? "amazonaws.com/eks/pause-windows:latest";
var kubeletExtraArgs = Environment.GetEnvironmentVariable("KUBELET_EXTRA_ARGS") ?? "";
var kubeProxyExtraArgs = Environment.GetEnvironmentVariable("KUBE_PROXY_EXTRA_ARGS") ?? "";
// This program starts with windows services on EC2 to bootstrap a EKS windows node
// It waits for userdata to become available and then extracts the necessary information to join the EKS cluster from the pwsh command
// It then prepares the node and starts the kubernetes components.
var EKSBinDir = Path.Combine(programFilesDirectory, "Amazon", "EKS");
var EKSDataDir = Path.Combine(programDataDirectory, "Amazon", "EKS");
var CNIBinDir = Path.Combine(EKSBinDir, "cni");
var CNIConfigDir = Path.Combine(EKSDataDir, "cni", "config");
var IAMAuthenticator = Path.Combine(EKSBinDir, "aws-iam-authenticator.exe");
var EKSClusterCACertFile = Path.Combine(EKSDataDir, "cluster_ca.crt");

var KubernetesBinDir = Path.Combine(programFilesDirectory, "kubernetes");
var KubernetesDataDir = Path.Combine(programDataDirectory, "kubernetes");
var Kubelet = Path.Combine(KubernetesBinDir, "kubelet.exe");
var Kubeproxy = Path.Combine(KubernetesBinDir, "kube-proxy.exe");
var CredentialProviderDir = Path.Combine(EKSBinDir, "credential-providers");
var CredentialProviderConfig = Path.Combine(EKSBinDir, "ecr-credential-provider-config.json");

// Initializing values for service restart parameters.
var SERVICE_FAILURE_COUNT_RESET_SEC = 300;
var SERVICE_FAILURE_FIRST_DELAY_MS = 5000;
var SERVICE_FAILURE_SECOND_DELAY_MS = 30000;
var SERVICE_FAILURE_THIRD_DELAY_MS = 60000;

// KUBECONFIG environment variable is set by Install-EKSWorkerNode.ps1
var KubeConfigFile = Environment.GetEnvironmentVariable("KUBECONFIG", EnvironmentVariableTarget.Machine) ?? Path.Combine(KubernetesDataDir, "kubeconfig");

// Kubelet configuration file
var KubeletConfigFile = Path.Combine(KubernetesDataDir, "kubelet-config.json");

var RestartTaskName = "EKS Windows cleanup and startup task";
var StartupTaskName = "EKS Windows startup task";


// Service host to host kubelet and kube-proxy
var ServiceHostExe = Path.Combine(EKSBinDir, "EKS-WindowsServiceHost.exe");

// User defined environment variables
var serviceIpv4CIDREnvVar = Environment.GetEnvironmentVariable("SERVICE_IPV4_CIDR", EnvironmentVariableTarget.Machine); // e.g. '10.100.0.0/16'
var excludedSnatCIDRsEnvVar = Environment.GetEnvironmentVariable("EXCLUDED_SNAT_CIDRS", EnvironmentVariableTarget.Machine); // e.g. '172.40.0.0/24,192.168.40.0/24'

var client = new Amazon.EKS.AmazonEKSClient();
var ec2Client = new Amazon.EC2.AmazonEC2Client();

var clusterTask = client.DescribeClusterAsync(new Amazon.EKS.Model.DescribeClusterRequest
{
    Name = clusterName
});

var instanceId = Amazon.Util.EC2InstanceMetadata.InstanceId;
var instanceInfoTask = ec2Client.DescribeInstancesAsync(new Amazon.EC2.Model.DescribeInstancesRequest
{
    InstanceIds = new List<string> { instanceId }
});
var region = Amazon.Util.EC2InstanceMetadata.Region.SystemName;
var eniMACAddress = Amazon.Util.EC2InstanceMetadata.GetData("/mac");
var vpcCIDRRange = Amazon.Util.EC2InstanceMetadata.GetData($"/network/interfaces/macs/{eniMACAddress}/vpc-ipv4-cidr-block");
var subnetCIDRRange = Amazon.Util.EC2InstanceMetadata.GetData($"/network/interfaces/macs/{eniMACAddress}/subnet-ipv4-cidr-block");
var subnetMaskBits = subnetCIDRRange.Split("/", 2)[1];
var internalIp = Amazon.Util.EC2InstanceMetadata.PrivateIpAddress;
var hostname = Amazon.Util.EC2InstanceMetadata.Hostname;

var cluster = await clusterTask;
var clusterEndpoint = cluster.Cluster.Endpoint;
var clusterCertificateAuthorityData = cluster.Cluster.CertificateAuthority.Data;
var serviceCIDR = cluster.Cluster.KubernetesNetworkConfig.ServiceIpv4Cidr ?? "10.100.0.0/16";
var gatewayIpAddresses = GetGatewayIpAddresses();
var instanceInfo = await instanceInfoTask;
var privateDnsName = instanceInfo.Reservations[0].Instances[0].PrivateDnsName;

stopWatch.Stop();
Console.WriteLine($"Gathered system configuration in {stopWatch.ElapsedMilliseconds} ms");
stopWatch.Reset();

Console.WriteLine("Configuring EKS Windows Node");
stopWatch.Start();
var startServiceTask = StartService("containerd");
await Task.WhenAll(
    UpdateKubeConfig(),
    UpdateEksCniConfig(),
    UpdateKubeletConfig(),
    RegisterKubernetesServices(),
    GenerateResolvConf()
);
await Task.WhenAll(
    EnableScheduledTask(RestartTaskName), 
    EnableScheduledTask(StartupTaskName), 
    startServiceTask);

await StartScheduledTask(StartupTaskName);

stopWatch.Stop();
Console.WriteLine($"EKS Windows Node Configured in {stopWatch.ElapsedMilliseconds} ms");

#region: Functions

IEnumerable<string> GetGatewayIpAddresses(){
    var netRoutes = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
    foreach (var netRoute in netRoutes)
    {
        var ipProperties = netRoute.GetIPProperties();
        var gateways = ipProperties.GatewayAddresses;
        foreach (var gateway in gateways)
        {
            if (gateway.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                yield return gateway.Address.ToString();
            }
        }
    }
}

List<string> GetCombinedSNATExclusionList()
{
    List<string> combinedCIDRRange = [vpcCIDRRange];
    if (!string.IsNullOrEmpty(excludedSnatCIDRsEnvVar))
    {
        Console.WriteLine("Excluding environment variable specified CIDR ranges for SNAT in CNI config");
        combinedCIDRRange.AddRange(excludedSnatCIDRsEnvVar.Split(","));
    }

    return combinedCIDRRange;
}

async Task UpdateKubeConfig()
{
    var caFileWriteTask =  File.WriteAllBytesAsync(EKSClusterCACertFile, Convert.FromBase64String(clusterCertificateAuthorityData));
    var kubeConfig = $@"
    apiVersion: v1
    kind: Config
    clusters:
    - cluster:
        certificate-authority: {EKSClusterCACertFile}
        server: {clusterEndpoint}
      name: kubernetes
    contexts:
    - context:
        cluster: kubernetes
        user: kubelet
      name: kubelet
    current-context: kubelet
    users:
    - name: kubelet
      user:
        exec:
          apiVersion: {apiVersionAuthentication}
          command: {IAMAuthenticator}
          args:
            - ""token""
            - ""-i""
            - ""{clusterName}""
            - --region
            - ""{region}""
    ";

    await Task.WhenAll(
        File.WriteAllTextAsync(KubeConfigFile, kubeConfig, Encoding.ASCII),
        caFileWriteTask
    );
}

async Task UpdateEksCniConfig()
{
    var CNIConfigFile = $"{CNIConfigDir}\\vpc-bridge.conf";
    List<string> SNATExcludedCIDRs = GetCombinedSNATExclusionList();
    var dnsSuffixList = new[] {"{%namespace%}.svc.cluster.local","svc.cluster.local","cluster.local"};
    var cniSpecVersion = "0.4.0";
    var additionalCNIConf = @"
        ""disableCheck"": true,
    ";

    var CNIConfig = $@"
    {{
        ""cniVersion"": ""{cniSpecVersion}"",
        ""name"": ""vpc"",
        ""type"": ""vpc-bridge"",
        ""capabilities"": {{""portMappings"": true}},{additionalCNIConf}
        ""eniMACAddress"": ""{eniMACAddress}"",
        ""eniIPAddresses"": [""{internalIp}/{subnetMaskBits}""],
        ""gatewayIPAddress"": ""{gatewayIpAddresses.FirstOrDefault()}"",
        ""vpcCIDRs"": [{string.Join(',', SNATExcludedCIDRs.Select(cidr => $"\"{cidr}\""))}],
        ""serviceCIDR"": ""{serviceCIDR}"",
        ""dns"": {{
            ""nameservers"": [""{dnsClusterIP}""],
            ""search"": [{string.Join(',', dnsSuffixList.Select(suffix => $"\"{suffix}\""))}]
        }}
    }}
    ";

    await File.WriteAllTextAsync(CNIConfigFile, CNIConfig, Encoding.ASCII);
}

async Task UpdateKubeletConfig()
{
    var KubeletConfig = @"
    {
        ""kind"": ""KubeletConfiguration"",
        ""apiVersion"": ""kubelet.config.k8s.io/v1beta1"",
        ""address"": ""0.0.0.0"",
        ""authentication"": {
            ""anonymous"": {
                ""enabled"": false
            },
            ""webhook"": {
                ""cacheTTL"": ""2m0s"",
                ""enabled"": true
            },
            ""x509"": {
                ""clientCAFile"": """ + EKSClusterCACertFile.Replace("\\", "\\\\") + @"""
            }
        },
        ""authorization"": {
            ""mode"": ""Webhook"",
            ""webhook"": {
                ""cacheAuthorizedTTL"": ""5m0s"",
                ""cacheUnauthorizedTTL"": ""30s""
            }
        },
        ""clusterDomain"": ""cluster.local"",
        ""hairpinMode"": ""hairpin-veth"",
        ""cgroupDriver"": ""cgroupfs"",
        ""cgroupRoot"": ""/"",
        ""featureGates"": {
            ""RotateKubeletServerCertificate"": true
        },
        ""serializeImagePulls"": false,
        ""serverTLSBootstrap"": true,
        ""clusterDNS"": [
            """ + dnsClusterIP + @"""
        ]
    }
    ";

    await File.WriteAllTextAsync(KubeletConfigFile, KubeletConfig, Encoding.ASCII);
}


async Task RegisterKubernetesServices()
{
    var kubeletArgs = new StringBuilder();
    kubeletArgs.Append(" --config=\\\"" + KubeletConfigFile + "\\\"");
    kubeletArgs.Append(" --cloud-provider=external");
    kubeletArgs.Append(" --kubeconfig=\\\"" + KubeConfigFile + "\\\"");
    kubeletArgs.Append(" --hostname-override=" + privateDnsName);
    kubeletArgs.Append(" --v=1");
    kubeletArgs.Append(" --pod-infra-container-image=\\\"" + eksPauseImage + "\\\"");
    kubeletArgs.Append(" --resolv-conf=\\\"\\\"");
    kubeletArgs.Append(" --enable-debugging-handlers");
    kubeletArgs.Append(" --cgroups-per-qos=false");
    kubeletArgs.Append(" --enforce-node-allocatable=\\\"\\\"");
    kubeletArgs.Append(" --container-runtime-endpoint=\\\"npipe:////./pipe/containerd-containerd\\\"");
    kubeletArgs.Append(" --image-credential-provider-bin-dir=\\\"" + CredentialProviderDir + "\\\"");
    kubeletArgs.Append(" --image-credential-provider-config=\\\"" + CredentialProviderConfig + "\\\"");
    kubeletArgs.Append(" --node-ip=" + internalIp);

    kubeletArgs.Append(" " + kubeletExtraArgs.Replace("\"", "\\\""));

    // Register the windows service
    var kubeletServiceName = "kubelet";
    var kubeProxyServiceName = "kube-proxy";
    
    var kubeletTask = Task.Run(() => {
        using var process = Process.Start(new ProcessStartInfo("sc.exe")
        {
            Arguments = $"create \"{kubeletServiceName}\" binPath= \"\\\"{ServiceHostExe}\\\" {kubeletServiceName} \\\"{Kubelet}\\\" {kubeletArgs}\" start= demand",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        });
        process?.WaitForExit();
        using var configure = Process.Start("sc.exe", $"failure {kubeletServiceName} reset={SERVICE_FAILURE_COUNT_RESET_SEC} actions=\"restart/{SERVICE_FAILURE_FIRST_DELAY_MS} + /restart/{SERVICE_FAILURE_SECOND_DELAY_MS} + /restart/{SERVICE_FAILURE_THIRD_DELAY_MS}\"");
        configure?.WaitForExit();
        using var failure = Process.Start("sc.exe", $"failureflag {kubeletServiceName} 1");
        failure?.WaitForExit();
    });


    var kubeProxyArgs = string.Join(" ", new[]
    {
        $"--kubeconfig=\\\"{KubeConfigFile}\\\"",
        "--v=1",
        "--proxy-mode=kernelspace",
        $"--hostname-override=\\\"{privateDnsName}\\\"",
        $"--cluster-cidr=\\\"{vpcCIDRRange}\\\"",
        kubeProxyExtraArgs
    });

    var kubeProxyTask = Task.Run(() => {
        using var process = Process.Start(new ProcessStartInfo("sc.exe")
        {
            Arguments = $"create {kubeProxyServiceName} binPath= \"\\\"{ServiceHostExe}\\\" {kubeProxyServiceName} \\\"{Kubeproxy}\\\" {kubeProxyArgs}\" start= demand",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        });
        process?.WaitForExit();
        using var configure = Process.Start("sc.exe", $"failure {kubeProxyServiceName} reset={SERVICE_FAILURE_COUNT_RESET_SEC} actions=\"restart/{SERVICE_FAILURE_FIRST_DELAY_MS} + /restart/{SERVICE_FAILURE_SECOND_DELAY_MS} + /restart/{SERVICE_FAILURE_THIRD_DELAY_MS}\"");
        configure?.WaitForExit();
        using var failure = Process.Start("sc.exe", $"failureflag {kubeProxyServiceName} 1");
        failure?.WaitForExit();
    });
    await Task.WhenAll(kubeletTask, kubeProxyTask);
}

async Task GenerateResolvConf()
{
    string resolvDir = @"c:\etc";
    string resolvFile = Path.Combine(resolvDir, "resolv.conf");

    // Creating resolv dir, if it doesn't exist
    if (!Directory.Exists(resolvDir))
    {
        Console.WriteLine($"Creating resolv directory: {resolvDir}");
        Directory.CreateDirectory(resolvDir);
    }

    // Getting unique comma separated Dns servers from the Ipv4 network interfaces (AddressFamily 2 represents IPv4)
    string[] dnsServers = NetworkInterface.GetAllNetworkInterfaces()
        .Where(ni => ni.Supports(NetworkInterfaceComponent.IPv4))
        .SelectMany(ni => ni.GetIPProperties().DnsAddresses)
        .Where(ip => ip.AddressFamily == AddressFamily.InterNetwork)
        .Select(ip => ip.ToString())
        .Distinct()
        .ToArray();

    string resolvContent = $"nameserver {string.Join(",", dnsServers)}";
    await File.WriteAllTextAsync(resolvFile, resolvContent, Encoding.ASCII);
}

async Task EnableScheduledTask(string taskName)
{
    var process = Process.Start("schtasks.exe", $"/change /tn \"{taskName}\" /enable");
    if(process != null)
    {
        await process.WaitForExitAsync();
    }
}

async Task StartScheduledTask(string taskName)
{
    var process = Process.Start("schtasks.exe", $"/run /tn \"{taskName}\"");
    if(process != null)
    {
        await process.WaitForExitAsync();
    }
}

async Task StartService(string serviceName)
{
    var process = Process.Start("sc.exe", $"start {serviceName}");
    if(process != null)
    {
        await process.WaitForExitAsync();
    }
}
#endregion