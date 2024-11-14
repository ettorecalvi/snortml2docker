# snortml2docker

This is an experimental configuration of Snort3, integrating SnortML, a machine-learning-based module designed to detect and respond to unknown exploits by training a custom model. In this repository, you will find all the resources necessary to build and deploy the model. This setup follows Dr. Brandon Stultz’s SQL injection example (by Cisco Talos), which I recommend reading carefully before starting this project. You can find it here: https://blog.snort.org/2024/03/talos-launching-new-machine-learning.html. Additionally, there is a video that demonstrates the code execution with more theoretical background on machine learning.

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/ettorecalvi/snortml2docker.git && cd snortml2docker
   ```

2. Build the Docker image:
   ```bash
   docker build -t snort3ml .
   ```

3. Create a new container based on the image:
   ```bash
   docker run -it --name snort3ml_c snort3ml
   ```

   You will be immediately prompted into the shell (`CMD ["/bin/bash"]`).

For subsequent launches:

- Start the container:
  ```bash
  docker start snort3ml_c
  ```

- Open a shell inside the container:
  ```bash
  docker exec -it snort3ml_c /bin/bash
  ```

Navigate to the folder:
```bash
cd /usr/local/src/libml/examples/classifier
```

Here you will find:

- `pcapgen.py`: A Python script to generate a .pcap simulation file.
- `local.rules`: Contains the regex rules applied in the IPS.
- `train.py`: A Python script that builds the machine learning model.
- `classifier.cc` and `CMakeLists.txt`: These are not needed for this setup.

## Step 1: Generating a Simulated SQL Injection Traffic File

The `pcapgen.py` script, based on Scapy, simulates malicious traffic. It generates a `.pcap` file that includes a TCP client-server handshake: SYN (Client -> Server), SYN-ACK (Server -> Client), and a malicious request to the server:

```
GET /php/admin_notification.php?foo=1%27%20OR%202=3%2D%2D-- HTTP/1.1
```

The string `1%27%20OR%202=3%2D%2D` is an encoded URL representation of the SQL Injection `1' OR 2=3--`.

To execute the script:

1. Create a Python virtual environment:
   ```bash
   python3 -m venv venv
   ```

2. Activate the environment:
   ```bash
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install scapy
   ```

4. Run the script:
   ```bash
   python3 pcapgen.py
   ```

You can verify the generated traffic in the .pcap file with tcpdump (already installed):

```bash
tcpdump -r simulated_sql_injection.pcap
```

## Step 2: Configuring Local Rules

The `local.rules` file provides Snort with a specific regex rule that will alert on HTTP packets containing that pattern in the URL. The regex `/1%27%20OR%201=1%2D%2D/i` is intentionally specific, so the IPS will detect only packets with that exact string in the URL (`1' OR 1=1--`).

Example rule in `local.rules`:

```plaintext
alert http any any -> any 80 (
    msg:"SQL Injection Attempt Detected - Advanced Pattern";
    flow:to_server,established;
    http_uri:path;
    content:"/php/admin_notification.php", nocase;
    http_uri:query;
    content:"foo=", nocase;
    pcre:"/1%27%20OR%201=1%2D%2D/i";
    reference:cve,2012-2998;
    classtype:web-application-attack;
    sid:1;
)
```

## Step 3: Training the Model

The model will be trained on a simple dataset as demonstrated in Dr. Brandon Stultz’s tutorial:

```python
data = [
    { 'str': 'foo=1', 'attack': 0 },
    { 'str': 'foo=1%27%20OR%201=1%2D%2D', 'attack': 1 }  # attack == 1 means this item is malicious
]
```

You can add additional records; note that the computational time will increase linearly as the dataset grows.

To train the model, install the necessary Python dependencies:

```bash
pip install numpy tensorflow
```

Then run the training script:

```bash
./train.py
```

## Step 4: Running Snort with the Model

Now you have all the components needed to run Snort using `snort_ml_engine`.

Execute Snort with this command:

```bash
snort -c /usr/local/snort/etc/snort/snort.lua --talos --lua 'snort_ml_engine = { http_param_model = "classifier.model" }; snort_ml = {}; trace = { modules = { snort_ml = {all =1 } } };' -r simulated_sql_injection.pcap
```

- `-c /usr/local/snort/etc/snort/snort.lua`: Links to the basic Snort3 configuration file.
- `--talos --lua`: Adds extra options to the Lua module, passing in `snort_ml_engine` with the `http_param_model`, which is the only model available at the moment (November 2024).

## Explanation of Model Functionality

As explained in the linked resources: "The `http_param_model` is used for classifying HTTP parameters as malicious or normal. Once loaded by the `snort_ml_engine`, the model can be used in the SnortML inspector to detect exploits."

The inspector subscribes to HTTP request data, passing it to a binary classifier based on `http_param_model`. This classifier then returns the probability that an exploit was detected. Based on this probability, SnortML can generate an alert similar to a Snort rule alert, blocking malicious traffic if configured.

## Observing Output

The output provides information on rule matches and Snort ML alerts.

Example output for no detection in IPS due to regex mismatch (`1' OR 1=1--` vs `1' OR 2=3--`):

```plaintext
rule profile (all, sorted by total_time)
#       gid   sid rev    checks matches alerts time (us) avg/check avg/match avg/non-match timeouts suspends rule_time (%)
=       ===   === ===    ====== ======= ====== ========= ========= ========= ============= ======== ======== =============
1         1     1   0         1       0      0       112       112         0           112        0        0       0.2451
```

Snort ML alert section:

```plaintext
--------------------------------------------------
snort_ml
               uri_alerts: 1
                uri_bytes: 17
              libml_calls: 1
--------------------------------------------------
```

Snort ML detected the malicious query `foo=1' OR 2=3--` due to its similarity to the training item `foo=1%27%20OR%201=1%2D%2D`. The `0.96` value represents the confidence level, which triggered the alert.

```plaintext
dump:pcap DAQ configured to inline.
Commencing packet processing
++ [0] simulated_sql_injection.pcap
P0:snort_ml:classifier:1: input (query): foo=1' OR 2=3----
P0:snort_ml:classifier:1: output: 0.964244
P0:snort_ml:classifier:1: <ALERT>
```

## Conclusion:
In this example, we observed a trained model capable of detecting and (in the future) potentially stopping unknown attacks. This setup demonstrates a static version of what this model could achieve. In a "production mode," it would be possible to continuously train the model by adding newly discovered malicious strings, enhancing the confidence and effectiveness of its operation.

I would like to thank the Snort 3.0 Team for developing and maintaining this open model. You can find their GitHub repository here: https://github.com/snort3, and join the Discord community here: https://discord.com/channels/856942140880977971/856942141643948055.