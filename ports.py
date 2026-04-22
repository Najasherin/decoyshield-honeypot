import random

def generate_ports():

    # 50 commonly used ports
    common_ports = [
        20,21,22,23,25,53,67,68,69,80,
        88,110,119,123,137,138,139,143,161,179,
        194,389,427,443,445,465,500,512,513,514,
        515,520,548,554,587,636,989,990,993,995,
        1080,1433,1521,2049,2082,2083,2086,2087,2181,1111,2222,3333,4444,5555,6666
    ]

    additional_ports = random.sample(range(10000, 60000), 50)

    all_ports = list(set(common_ports + additional_ports))

    return all_ports