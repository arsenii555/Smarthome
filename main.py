import requests
import sys
import time

HUB_SERIAL = 1
URL = sys.argv[1]
SRC = sys.argv[2]
next_request = []
Sensors = {}
Network_map = {}
LampSockets = {}
Switchs = {}
timer = 0


def byte_to_int(s):
    return int(s, 16)


def calculate_crc8(data):
    data = list(map(byte_to_int, data))
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0x1d
            else:
                crc <<= 1
    return crc & 0xFF


def bytes_to_base64(bytes):
    alfabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    bytes_bin = ""
    for i in bytes:
        bytes_bin += ("0" * (8 - len(bin(int(i, 16))[2:])) + bin(int(i, 16))[2:])
    count = ((6 - len(bytes_bin) % 6) % 6)
    bytes_bin += "0" * count
    res = ""
    respart = ""
    for i in range(len(bytes_bin)):
        respart += bytes_bin[i]
        if (i + 1) % 6 == 0:
            res += alfabet[int(respart, 2)]
            respart = ""
    return res


def str_to_bytes(s):
    bytes = []
    bytes.append("0" * ((2 - len(hex(len(s))[2:])) % 2) + hex(len(s))[2:])
    for i in s:
        bytes.append(("0" * ((2 - len(hex(ord(i))[2:])) % 2) + hex(ord(i))[2:]))
    return bytes


def base64_to_bytes(base):
    base = base.replace("+", "-").replace("/", "_")
    count = ((8 - len(base) % 8) % 8)
    dic2 = dict()
    alfabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    for i in range(len(alfabet)):
        dic2[alfabet[i]] = hex(i)[2:]
    ans_bin = ""
    for i in base:
        if i != "=":
            ans_bin += ("0" * (6 - len(bin(int(dic2[i], 16))[2:])) + bin(int(dic2[i], 16))[2:])
    ans_bin += "0" * count * 2
    ans_bin = ans_bin[:len(ans_bin) - count * 2]
    res = []
    respart = ""
    for i in range(len(ans_bin)):
        respart += ans_bin[i]
        if (i + 1) % 8 == 0:
            res.append(respart)
            respart = ""
    for i in range(len(res)):
        res[i] = hex(int(res[i], 2))[2:]
        if len(res[i]) < 2:
            res[i] = "0" + res[i]
    return res


def int_to_uleb128(x):
    bin_x = "0" * ((7 - len(bin(x)[2:]) % 7) % 7) + bin(x)[2:]
    res = []
    respart = ""
    for i in range(len(bin_x)):
        respart += bin_x[i]
        if (i + 1) % 7 == 0:
            res.append(respart)
            respart = ""
    res[0] = "0" + res[0]
    res[0] = "0" * (2 - len(hex(int(res[0], 2))[2:])) + hex(int(res[0], 2))[2:]
    for i in range(1, len(res)):
        res[i] = "1" + res[i]
        res[i] = "0" * (2 - len(hex(int(res[i], 2))[2:])) + hex(int(res[i], 2))[2:]
    return res[::-1]


def uleb128_to_int(bytes):
    ans = 0
    sdvig = 0
    bytesread = 0
    while sdvig <= 63 and bytesread < len(bytes):
        b = int(bytes[bytesread], 16)
        bytesread += 1
        ans |= (b & 0x7F) << sdvig
        if b & 0x80 == 0:
            break
        sdvig += 7
    return ans, bytesread


def bytes_to_dict(bytes):
    length = int(bytes[0], 16)
    crc8 = int(bytes[length + 1], 16)
    src, len1 = uleb128_to_int(bytes[1:])
    dst, len2 = uleb128_to_int(bytes[len1 + 1:])
    serial, len3 = uleb128_to_int(bytes[len1 + len2 + 1:])
    dev_type = int(bytes[len1 + len2 + len3 + 1], 16)
    cmd = int(bytes[len1 + len2 + len3 + 2], 16)
    cmd_body_begin = len1 + len2 + len3 + 3
    dic = dict()
    dic["length"] = length
    dic["payload"] = {
        "src": src,
        "dst": dst,
        "serial": serial,
        "dev_type": dev_type,
        "cmd": cmd,
        "cmd_body": {}
    }
    if dev_type == 1:
        if cmd == 1 or cmd == 2:
            strlen = int(bytes[cmd_body_begin], 16)
            dev_name = ""
            for i in bytes[cmd_body_begin + 1: cmd_body_begin + 1 + strlen]:
                dev_name += chr(int(i, 16))
            dic["payload"]["cmd_body"]["dev_name"] = dev_name
    elif dev_type == 2:
        if cmd == 1 or cmd == 2:
            strlen = int(bytes[cmd_body_begin], 16)
            dev_name = ""
            for i in bytes[cmd_body_begin + 1: cmd_body_begin + 1 + strlen]:
                dev_name += chr(int(i, 16))
            dic["payload"]["cmd_body"]["dev_name"] = dev_name
            cmd_body_sensors = cmd_body_begin + 1 + strlen
            dic["payload"]["cmd_body"]["dev_props"] = {}
            dic["payload"]["cmd_body"]["dev_props"]["sensors"] = int(bytes[cmd_body_sensors], 16)
            dic["payload"]["cmd_body"]["dev_props"]["triggers"] = list()
            dim_triggers = int(bytes[cmd_body_sensors + 1], 16)
            cmd_body_triggers = cmd_body_sensors + 2
            for _ in range(dim_triggers):
                d = dict()
                d["op"] = int(bytes[cmd_body_triggers], 16)
                d["value"], len_value = uleb128_to_int(bytes[cmd_body_triggers + 1:])
                strlen = int(bytes[cmd_body_triggers + 1 + len_value], 16)
                name = ""
                for i in bytes[cmd_body_triggers + 2 + len_value: cmd_body_triggers + 2 + len_value + strlen]:
                    name += chr(int(i, 16))
                d["name"] = name
                cmd_body_triggers = cmd_body_triggers + 2 + len_value + strlen
                dic["payload"]["cmd_body"]["dev_props"]["triggers"].append(d)
        elif cmd == 4:
            dic["payload"]["cmd_body"]["values"] = []
            dim_values = int(bytes[cmd_body_begin], 16)
            for _ in range(dim_values):
                value, len_value = uleb128_to_int(bytes[cmd_body_begin + 1:])
                dic["payload"]["cmd_body"]["values"].append(value)
                cmd_body_begin += len_value
    elif dev_type == 3:
        if cmd == 1 or cmd == 2:
            strlen = int(bytes[cmd_body_begin], 16)
            dev_name = ""
            for i in bytes[cmd_body_begin + 1: cmd_body_begin + 1 + strlen]:
                dev_name += chr(int(i, 16))
            dic["payload"]["cmd_body"]["dev_name"] = dev_name
            dic["payload"]["cmd_body"]["dev_props"] = {}
            dic["payload"]["cmd_body"]["dev_props"]["dev_names"] = []
            len_names = int(bytes[cmd_body_begin + 1 + strlen], 16)
            names_begin = cmd_body_begin + 2 + strlen
            for _ in range(len_names):
                len_name = int(bytes[names_begin], 16)
                name = ""
                for i in bytes[names_begin + 1: names_begin + 1 + len_name]:
                    name += chr(int(i, 16))
                dic["payload"]["cmd_body"]["dev_props"]["dev_names"].append(name)
        elif cmd == 4:
            dic["payload"]["cmd_body"]["value"] = int(bytes[cmd_body_begin], 16)
    elif dev_type == 4 or dev_type == 5:
        if cmd == 1 or cmd == 2:
            strlen = int(bytes[cmd_body_begin], 16)
            dev_name = ""
            for i in bytes[cmd_body_begin + 1: cmd_body_begin + 1 + strlen]:
                dev_name += chr(int(i, 16))
            dic["payload"]["cmd_body"]["dev_name"] = dev_name
        elif cmd == 4 or cmd == 5:
            dic["payload"]["cmd_body"]["value"] = int(bytes[cmd_body_begin], 16)
    elif dev_type == 6:
        if cmd == 2:
            strlen = int(bytes[cmd_body_begin], 16)
            dev_name = ""
            for i in bytes[cmd_body_begin + 1: cmd_body_begin + 1 + strlen]:
                dev_name += chr(int(i, 16))
            dic["payload"]["cmd_body"]["dev_name"] = dev_name
        elif cmd == 6:
            timestamp, len_timestamp = uleb128_to_int(bytes[cmd_body_begin:])
            dic["payload"]["cmd_body"]["timestamp"] = timestamp
    dic["crc8"] = crc8
    return dic


def base64_to_list_of_dicts(base):
    dicts = []
    bytes = base64_to_bytes(base)
    length_point = 0
    while length_point < len(bytes):
        l = int(bytes[length_point], 16)
        d = bytes_to_dict(bytes[length_point: length_point + 2 + l])
        length_point += (2 + l)
        dicts.append(d)
    return dicts


def NewSensor(n, s, sv, dt):
    sensor = {
        "name": n,
        "IsActivated": 1,
        "NetworkConnected": 1,
        "LastAccessTime": timer,
        "Sensors": s,
        "SensorsValue": sv,
        "DataTriggers": dt,
        "Sent": 1,
        "NanTriggers": 1
    }
    return sensor


def createSensorData(props):
    sensor_data_triggers = []
    for i in range(len(props["triggers"])):
        sensor = {
            "SensorIndex": int((props["triggers"][i]["op"] & 0x0c) >> 2),
            "TriggerFunction": props["triggers"][i]["op"] & 0x01,
            "TriggerGreater": (props["triggers"][i]["op"] & 0x02) >> 1,
            "TriggerValue": props["triggers"][i]["value"],
            "TriggerDevice": props["triggers"][i]["name"]
        }
        sensor_data_triggers.append(sensor)
    return sensor_data_triggers


def check_child_status(swi):
    for value in swi["DevicesConnected"]:
        if value in Network_map:
            exist = True
            address = Network_map[value]
        else:
            exist = False
            address = None
        if not exist:
            continue
        if LampSockets[address]["NetworkConnected"] == 0:
            continue
        setstatus_request(swi["IsActivated"], LampSockets[address], address)


def check_sensors_triggers(sen, newval):
    for value in sen["DataTriggers"]:
        if sen["Sensors"][value["SensorIndex"]] == 0:
            continue
        if value["TriggerDevice"] in Network_map:
            exist = True
            address = Network_map[value["TriggerDevice"]]
        else:
            exist = False
            address = None
        if not exist:
            continue
        if LampSockets[address]["NetworkConnected"] == 0:
            continue
        if (value["TriggerGreater"] == 1 and value["TriggerValue"] < newval[value["SensorIndex"]]) or (
                value["TriggerGreater"] == 0 and value["TriggerValue"] > newval["SensorIndex"]):
            setstatus_request(value["TriggerFunction"], LampSockets[address], address)


def check_crc8(bytes):
    return calculate_crc8(bytes) == 0


def check_response(bytes):
    return check_crc8(bytes[1:])


def handle_server_response(bytes):
    global Sensors
    global Network_map
    global Switchs
    global LampSockets
    global timer
    if not check_response(bytes):
        return
    dic = bytes_to_dict(bytes)
    if dic["payload"]["dev_type"] == 2:
        if dic["payload"]["cmd"] == 1:
            exist = dic["payload"]["src"] in Sensors
            if exist:
                Sensors.pop(dic["payload"]["src"], None)
            iamhere_request()
            exist = dic["payload"]["src"] in Sensors
            if exist:
                return
            Network_map[dic["payload"]["cmd_body"]["dev_name"]] = dic["payload"]["src"]
            received_sensor_props = dic["payload"]["cmd_body"]["dev_props"]
            s = [0] * 4
            sv = s
            j = 1
            for i in range(4):
                s[i] = (received_sensor_props["sensors"] & (j << i)) >> i
            newsensor = NewSensor(dic["payload"]["cmd_body"]["dev_name"], s, sv,
                                  createSensorData(received_sensor_props))
            Sensors[dic["payload"]["src"]] = newsensor
            getstatus_request(dic["payload"]["src"], dic["payload"]["dev_type"])
        elif dic["payload"]["cmd"] == 2:
            exist = dic["payload"]["src"] in Sensors
            if exist:
                return
            Network_map[dic["payload"]["cmd_body"]["dev_name"]] = dic["payload"]["src"]
            received_sensor_props = dic["payload"]["cmd_body"]["dev_props"]
            s = [0] * 4
            sv = s
            j = 1
            for i in range(4):
                s[i] = (received_sensor_props["sensors"] & (j << i)) >> i
            newsensor = NewSensor(dic["payload"]["cmd_body"]["dev_name"], s, sv,
                                  createSensorData(received_sensor_props))
            Sensors[dic["payload"]["src"]] = newsensor
            getstatus_request(dic["payload"]["src"], dic["payload"]["dev_type"])
        elif dic["payload"]["cmd"] == 4:
            if dic["payload"]["src"] in Sensors:
                exist = True
                val = Sensors[dic["payload"]["src"]]
            else:
                exist = False
                val = None
            if (exist and val["NetworkConnected"] == 0) or (val["Sent"] == 1 and (timer - val["LastAccessTime"]) > 300):
                val["NetworkConnected"] = 0
                Sensors[dic["payload"]["src"]] = val
                return
            received_sensor_status = dic["payload"]["cmd_body"]
            senval = Sensors[dic["payload"]["src"]]
            newval = [0] * 4
            j = 0
            for i in range(4):
                if senval["Sensors"][i] == 1:
                    newval[i] = received_sensor_status["values"][j]
                    j += 1
            check_sensors_triggers(senval, newval)
            senval["NanTriggers"] = 0
            senval["Sent"] = 0
            senval["SensorsValue"] = newval
            Sensors[dic["payload"]["src"]] = senval
        else:
            exit(99)
    elif dic["payload"]["dev_type"] == 3:
        if dic["payload"]["cmd"] == 1:
            exist = dic["payload"]["src"] in Switchs
            if exist:
                Switchs.pop(dic["payload"]["src"], None)
            iamhere_request()
            exist = dic["payload"]["src"] in Switchs
            if exist:
                return
            received_device = dic["payload"]["cmd_body"]
            Network_map[received_device["dev_name"]] = dic["payload"]["src"]
            received_connected_devices = received_device["dev_props"]
            Switchs[dic["payload"]["src"]] = {
                "Name": received_device["dev_name"],
                "IsActivated": 1,
                "NetworkConnected": 1,
                "LastAccessTime": timer,
                "DevicesConnected": received_connected_devices["dev_names"],
                "Sent": 1
            }
            getstatus_request(dic["payload"]["src"], dic["payload"]["dev_type"])
        elif dic["payload"]["cmd"] == 2:
            exist = dic["payload"]["src"] in Switchs
            if exist:
                return
            received_device = dic["payload"]["cmd_body"]
            Network_map[received_device["dev_name"]] = dic["payload"]["src"]
            received_connected_devices = received_device["dev_props"]
            Switchs[dic["payload"]["src"]] = {
                "Name": received_device["dev_name"],
                "IsActivated": 1,
                "NetworkConnected": 1,
                "LastAccessTime": timer,
                "DevicesConnected": received_connected_devices["dev_names"],
                "Sent": 1
            }
            getstatus_request(dic["payload"]["src"], dic["payload"]["dev_type"])
        elif dic["payload"]["cmd"] == 4:
            if dic["payload"]["src"] in Switchs:
                exist = True
                val = Switchs[dic["payload"]["src"]]
            else:
                exist = False
                val = None
            if (exist and val["NetworkConnected"] == 0) or (val["Sent"] == 1 and (timer - val["LastAccessTime"] > 300)):
                val["NetworkConnected"] = 0
                Switchs[dic["payload"]["src"]] = val
                return
            isactivated = dic["payload"]["cmd_body"]["value"]
            swival = Switchs[dic["payload"]["src"]]
            swival["IsActivated"] = isactivated
            swival["Sent"] = 0
            Switchs[dic["payload"]["src"]] = swival
            check_child_status(swival)
        else:
            exit(99)
    elif dic["payload"]["dev_type"] == 4 or dic["payload"]["dev_type"] == 5:
        if dic["payload"]["cmd"] == 1:
            exist = dic["payload"]["src"] in LampSockets
            if exist:
                LampSockets.pop(dic["payload"]["src"], None)
            iamhere_request()
            exist = dic["payload"]["src"] in LampSockets
            if exist:
                return
            received_device = dic["payload"]["cmd_body"]
            Network_map[received_device["dev_name"]] = dic["payload"]["src"]
            LampSockets[dic["payload"]["src"]] = {
                "Name": received_device["dev_name"],
                "IsActivated": 1,
                "LastAccessTime": timer,
                "NetworkConnected": 1,
                "DevType": dic["payload"]["dev_type"],
                "Sent": 1
            }
            getstatus_request(dic["payload"]["src"], dic["payload"]["dev_type"])
        elif dic["payload"]["cmd"] == 2:
            exist = dic["payload"]["src"] in LampSockets
            if exist:
                return
            received_device = dic["payload"]["cmd_body"]
            Network_map[received_device["dev_name"]] = dic["payload"]["src"]
            LampSockets[dic["payload"]["src"]] = {
                "Name": received_device["dev_name"],
                "IsActivated": 1,
                "LastAccessTime": timer,
                "NetworkConnected": 1,
                "DevType": dic["payload"]["dev_type"],
                "Sent": 1
            }
            getstatus_request(dic["payload"]["src"], dic["payload"]["dev_type"])
        elif dic["payload"]["cmd"] == 4:
            if dic["payload"]["src"] in LampSockets:
                val = LampSockets[dic["payload"]["src"]]
                exist = True
            else:
                val = None
                exist = False
            if exist:
                if (exist and val["NetworkConnected"] == 0) or (
                        val["Sent"] == 1 and (timer - val["LastAccessTime"] > 300)):
                    val["NetworkConnected"] = 0
                    LampSockets[dic["payload"]["src"]] = val
                    return
                isactivated = dic["payload"]["cmd_body"]["value"]
                deviceval = LampSockets[dic["payload"]["src"]]
                deviceval["IsActivated"] = isactivated
                deviceval["Sent"] = 0
                LampSockets[dic["payload"]["src"]] = deviceval
        else:
            exit(99)
    elif dic["payload"]["dev_type"] == 6:
        if dic["payload"]["cmd"] == 2:
            received_device = dic["payload"]["cmd_body"]
            Network_map[received_device["dev_name"]] = dic["payload"]["src"]
        elif dic["payload"]["cmd"] == 6:
            timer = dic["payload"]["cmd_body"]["timestamp"]
        else:
            exit(99)
    else:
        exit(99)


def send_request(bytes):
    global next_request
    base = bytes_to_base64(bytes)
    response = requests.post(URL, base)
    if response.status_code == 204:
        exit(0)
    elif response.status_code != 200:
        exit(99)
    data = base64_to_bytes(response.text)
    next_request = []
    i = 0
    while i < len(data):
        packet_length = int(data[i], 16)
        packet = data[i: i + packet_length + 2]
        handle_server_response(packet)
        i += 2 + packet_length


def whoishere_request():
    global HUB_SERIAL
    res_bytes = []
    src = SRC
    dst = 16383
    serial = HUB_SERIAL
    HUB_SERIAL += 1
    dev_type = 1
    cmd = 1
    dev_name = "HUB"
    payload_bytes = []
    payload_bytes += int_to_uleb128(int(src, 16))
    payload_bytes += int_to_uleb128(dst)
    payload_bytes += int_to_uleb128(serial)
    payload_bytes.extend([("0" * ((2 - len(hex(dev_type)[2:])) % 2) + hex(dev_type)[2:])])
    payload_bytes.extend([("0" * ((2 - len(hex(cmd)[2:])) % 2) + hex(cmd)[2:])])
    payload_bytes += str_to_bytes(dev_name)
    length = len(payload_bytes)
    crc8 = calculate_crc8(payload_bytes)
    res_bytes.append("0" * ((2 - len(hex(length)[2:])) % 2) + hex(length)[2:])
    res_bytes += payload_bytes
    res_bytes.append("0" * ((2 - len(hex(crc8)[2:])) % 2) + hex(crc8)[2:])
    send_request(res_bytes)


def getstatus_request(dst, dev_type):
    global HUB_SERIAL
    global next_request
    res_bytes = []
    src = SRC
    dst = dst
    serial = HUB_SERIAL
    HUB_SERIAL += 1
    dev_type = dev_type
    cmd = 3
    payload_bytes = []
    payload_bytes += int_to_uleb128(int(src, 16))
    payload_bytes += int_to_uleb128(dst)
    payload_bytes += int_to_uleb128(serial)
    payload_bytes.extend([("0" * ((2 - len(hex(dev_type)[2:])) % 2) + hex(dev_type)[2:])])
    payload_bytes.extend([("0" * ((2 - len(hex(cmd)[2:])) % 2) + hex(cmd)[2:])])
    length = len(payload_bytes)
    crc8 = calculate_crc8(payload_bytes)
    res_bytes.append("0" * ((2 - len(hex(length)[2:])) % 2) + hex(length)[2:])
    res_bytes += payload_bytes
    res_bytes.append("0" * ((2 - len(hex(crc8)[2:])) % 2) + hex(crc8)[2:])
    next_request += res_bytes


def iamhere_request():
    global HUB_SERIAL
    global next_request
    res_bytes = []
    src = SRC
    dst = 16383
    serial = HUB_SERIAL
    HUB_SERIAL += 1
    dev_type = 1
    cmd = 2
    dev_name = "HUB"
    payload_bytes = []
    payload_bytes += int_to_uleb128(int(src, 16))
    payload_bytes += int_to_uleb128(dst)
    payload_bytes += int_to_uleb128(serial)
    payload_bytes += "01"
    payload_bytes += "02"
    payload_bytes += str_to_bytes(dev_name)
    length = len(payload_bytes)
    crc8 = calculate_crc8(payload_bytes)
    res_bytes.append("0" * ((2 - len(hex(length)[2:])) % 2) + hex(length)[2:])
    res_bytes.append("0" * ((2 - len(hex(crc8)[2:])) % 2) + hex(crc8)[2:])
    next_request += res_bytes


def setstatus_request(isactive, dev, address):
    global LampSockets
    global HUB_SERIAL
    global next_request
    res_bytes = []
    val = LampSockets[address]
    val["Sent"] = 1
    val["LastAccessTime"] = timer
    LampSockets[address] = val
    src = SRC
    dst = address
    serial = HUB_SERIAL
    HUB_SERIAL += 1
    dev_type = dev["DevType"]
    cmd = 5
    cmd_body = isactive
    payload_bytes = []
    payload_bytes += int_to_uleb128(int(src, 16))
    payload_bytes += int_to_uleb128(dst)
    payload_bytes += int_to_uleb128(serial)
    payload_bytes.extend([("0" * ((2 - len(hex(dev_type)[2:])) % 2) + hex(dev_type)[2:])])
    payload_bytes.extend([("0" * ((2 - len(hex(cmd)[2:])) % 2) + hex(cmd)[2:])])
    payload_bytes.extend(["0" + str(cmd_body)])
    length = len(payload_bytes)
    crc8 = calculate_crc8(payload_bytes)
    res_bytes.append("0" * ((2 - len(hex(length)[2:])) % 2) + hex(length)[2:])
    res_bytes += payload_bytes
    res_bytes.append("0" * ((2 - len(hex(crc8)[2:])) % 2) + hex(crc8)[2:])
    next_request += res_bytes


def main():
    whoishere_request()
    while True:
        send_request(next_request)
main()