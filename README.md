# Smart Home Hub Simulator

This program simulates the functionality of a smart home hub to manage various devices within a smart home system. It communicates with the system through HTTP requests.

## Prerequisites

- Python 3.x
- Requests library (`pip install requests`)

## Usage

```bash
python hub_simulator.py <URL> <SRC>
```

- `<URL>`: The URL of the smart home system.
- `<SRC>`: Source address for communication.

## Functionality

The program simulates the following functionalities:

- **Device Discovery**: Identifies and registers devices within the smart home system.
- **Status Monitoring**: Monitors the status of devices including sensors, switches, and lamp sockets.
- **Control Operations**: Controls the activation status of devices.

## Implementation Details

The program is written in Python and includes the following functionalities:

- **Data Encoding/Decoding**: Functions to convert data between different formats like base64, bytes, and integers.
- **CRC Calculation**: Calculation of CRC8 checksum for data integrity.
- **Request Handling**: Sending and receiving requests to/from the smart home system.
- **Device Management**: Tracking and managing devices including sensors, switches, and lamp sockets.
- **Trigger Handling**: Handling triggers based on sensor data.

## Main Function

The `main()` function initiates the execution of the program. It starts by sending a "Who is here" request to discover devices and then continuously sends and receives requests to manage and monitor the smart home system.

## Note

This program is a simulation and does not interact with real devices. It is intended for educational purposes or as a prototype for developing a real smart home hub system.
