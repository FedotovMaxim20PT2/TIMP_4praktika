#include <iostream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include "Modules/AES.h"
#include "Modules/DES.h"
using namespace std;
using namespace CryptoPP;

int main ()
{
  cout << "~~~ File cryptor ~~~" << endl;

  unsigned op, cip;
  string FIn, FOut, Pass;

  do
  {
      cout << "\nEnter the operation (0 - exit, 1 - encrypt, 2 - decrypt): ";
      cin >> op;

      if (op != 0)
      {
        cout << "\nAvailable algorithms: " << endl;
        cout << "1 - AES-256" << endl;
        cout << "2 - DES" << endl;

        cout << "Choose algorithm and enter the number: ";
        cin >> cip;
      }

      if (op > 2)
      {
        cerr << "Error! Invalid operation\n";
      }

      else if (op > 0)
      {
        cout << "\nEnter a path to input file: ";
        cin >> FIn;

        cout << "\nEnter a path to output file: ";
        cin >> FOut;

        cout << "\nEnter a password: ";
        cin >> Pass;

        if (cip == 1)
        {
          AES_Cryptor aes(FIn, FOut, Pass);

          if (op == 1)
          {
            if (aes.AES_Encrypt())
              cout << "Successfull encrypting!" << endl;
            else
              cout << "Encryption failed!" << endl;
          } else {
            if (aes.AES_Decrypt())
              cout << "Successfull decrypting!" << endl;
            else
              cout << "Decryption failed!" << endl;
          }
        }

        else if (cip == 2)
        {
          DES_Cryptor des(FIn, FOut, Pass);

          if (op == 1)
          {
            if (des.DES_Encrypt())
              cout << "Successfull encrypting!" << endl;
            else
              cout << "Encryption failed!" << endl;
          } else {
            if (des.DES_Decrypt())
              cout << "Successfull decrypting!" << endl;
            else
              cout << "Decryption failed!" << endl;
          }
        }

        else
        {
          cerr << "Error! Incorrect algorithm number!!!\n";
        }
      }

  } while (op != 0);

  return 0;
}