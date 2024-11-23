# decompute-subnet

![decompute](https://media.discordapp.net/attachments/1239310439641387068/1305620071871418389/telechargement.jpeg?ex=6742da32&is=674188b2&hm=afd85aaf21a43008e9c1699b0f8131fbd1ae55c32fb3104e330ecd470c23043f&=&format=webp&width=824&height=877)

# How to Fake an Allocation

There's one main function to focus on:

https://github.com/neuralinternet/compute-subnet/blob/main/neurons/validator.py#L579

**execute_miner_checking_request**

Below is how it interacts with the miner, and what we've done to fake it:

1. Query the dendrite which calls this miner forward https://github.com/neuralinternet/compute-subnet/blob/main/neurons/miner.py#L428

2. The miner forward calls `check_allocation` or `check_if_allocated`:
   - For check_allocation, we modify this to check if our fake SSH server is running. The success return value for these functions are `{"status": True}`
   - If the validator did not specify checking=True, but did specify a docker_change or action, it will move onto here https://github.com/neuralinternet/compute-subnet/blob/main/neurons/miner.py#L446. These docker actions are all pretty simple. One gives a SSH key, another restarts the container, pause/unpause, etc. We mock all of these, as the success return value is simply `{"status": True}`

3. If there is an allocation, the validator will then, provided the status returned by the check allocation was True (i.e. you are allocated already), attempt to test the SSH port.

   - We fake this by having a dummy ssh server running. The validator check itself is just a simple socket test, there's no additional logic to it, technically just doing nc -l port would accomplish the same thing, it just expects _some_ response.

4. If the status is not true (you are not allocated), the validator then attempts to allocate your instance.

   - The valzidator calls the miner forward again, this time with checking=False, finally the miner will attempt to allocate a machine. This happens here: https://github.com/neuralinternet/compute-subnet/blob/main/neurons/miner.py#L470
   - `register_allocation` calls `run_container`. This is where the bulk of our changes are to fake the allocation. The expected result of `run_container` is simply `{"status": True, "info": encrypted_info}` where encrypted_info is an encrypted string of a dictionary dumped to json `info = {"username": "root", "password": password, "port": docker_ssh_port}`
  
5. Once the validator retrieves the encrypted username, password, and port, it will attempt to test the ssh access of the machine via `check_ssh_login`.

6. `check_ssh_login` uses paramiko to perform a ssh connection to the machine.
   - This connection passes as our fake ssh server can respond to ssh connection requests. I opted to use paramiko to create the fake ssh server as it only seems fitting.

Proof of concept logic that incorporates these changes:

https://github.com/cxmplex/decompute-subnet/blob/main/neurons/Miner/container.py

# How to make a secure compute subnet

**10t/hr**
