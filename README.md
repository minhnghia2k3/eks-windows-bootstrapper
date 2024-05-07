# EKS Windows Bootstrapper

The EKS Windows Bootstrapper is a fast and efficient tool for bootstrapping Windows nodes in Amazon Elastic Kubernetes Service (EKS). It is written in C#/.NET and is designed to work seamlessly with Karpenter, a popular Kubernetes node autoscaler.

## Features

- Fast and efficient bootstrapping of Windows nodes in EKS
- Seamless integration with Karpenter for automatic node scaling
- Easy to use and configure

## Usage

Use AWS Image Builder to create a custom AMI with the boostrapper installed. You can use the AMIs in a Karpenter Ec2NodeClass.

- [Image Builder Instructions](https://github.com/your-username/eks-windows-bootstrapper/wiki)

## Prerequisites

Before using the EKS Windows Bootstrapper, make sure you have the following prerequisites installed:

- .NET SDK (version 8 or higher)
- Visual Studio 2022, including the Desktop development with C++ workload with all default components.

## Getting Started

To get started with the EKS Windows Bootstrapper, follow these steps:

1. Clone the repository:

    ```shell
    git clone https://github.com/your-username/eks-windows-bootstrapper.git
    ```

2. Navigate to the project directory:

    ```shell
    cd eks-windows-bootstrapper
    ```

3. Build the project:

    ```shell
    dotnet build
    ```

For more detailed instructions and advanced usage, please refer to the [documentation](https://github.com/your-username/eks-windows-bootstrapper/wiki).

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request on the [GitHub repository](https://github.com/your-username/eks-windows-bootstrapper).

## License

This project is licensed under the [MIT License](LICENSE).