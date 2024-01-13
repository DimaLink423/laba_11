using System;
using System.Numerics;
using System.Security.Cryptography;

class Program
{
    //------------
    static void GeneratePrimeNumbers(out BigInteger primeP, out BigInteger primeQ)
    {
        primeQ = GenerateProbablePrime(160);
        BigInteger k = BigInteger.Zero;
        BigInteger tempP;
        do{k++;
            tempP = k * primeQ + 1;
        } while (!IsProbablePrime(tempP, 10));
        primeP = tempP;
    }
    static void GenerateGenerator(BigInteger primeP, BigInteger primeQ, out BigInteger generatorG)
    {
    BigInteger h;
        do
        {
            h = BigInteger.ModPow(RandomBigInteger(2, primeP - 2), (primeP - 1) / primeQ, primeP);
        } while (h == 1);

        generatorG = BigInteger.ModPow(h, (primeP - 1) / primeQ, primeP);
    }

    static void GenerateKeyPair(BigInteger primeP, BigInteger primeQ, BigInteger generatorG, out BigInteger privateKeyX, out BigInteger publicKeyY)
    {
        privateKeyX = RandomBigInteger(2, primeQ - 1);
        publicKeyY = BigInteger.ModPow(generatorG, privateKeyX, primeP);
    }

    static BigInteger[] SignMessage(string message, BigInteger primeP, BigInteger primeQ, BigInteger generatorG, BigInteger privateKeyX)
    {
        BigInteger k;
        BigInteger[] signature = new BigInteger[2];

        do
        {
            do
            {
                k = RandomBigInteger(2, primeQ - 1);
            } while (k == 0);

            signature[0] = BigInteger.ModPow(generatorG, k, primeP) % primeQ;
            signature[1] = (ModInverse(k, primeQ) * (HashMessage(message) + privateKeyX * signature[0])) % primeQ;

        } while (signature[0] == 0 || signature[1] == 0);

        return signature;
    }

    static bool VerifySignature(string message, BigInteger r, BigInteger s, BigInteger primeP, BigInteger primeQ, BigInteger generatorG, BigInteger publicKeyY)
    {
        if (r < 1 || r > primeQ - 1 || s < 1 || s > primeQ - 1)
            return false;

        BigInteger w = ModInverse(s, primeQ);
        BigInteger u1 = (HashMessage(message) * w) % primeQ;
        BigInteger u2 = (r * w) % primeQ;

        u1 = (u1 + primeQ) % primeQ;
        u2 = (u2 + primeQ) % primeQ;

        BigInteger v = ((BigInteger.ModPow(generatorG, u1, primeP) * BigInteger.ModPow(publicKeyY, u2, primeP)) % primeP) % primeQ;

        return v == r;
    }

    static BigInteger HashMessage(string message)
    {
        using (SHA1Managed sha1 = new SHA1Managed())
        {
            byte[] hashBytes = sha1.ComputeHash(System.Text.Encoding.UTF8.GetBytes(message));
            Array.Resize(ref hashBytes, hashBytes.Length + 1);
            hashBytes[hashBytes.Length - 1] = 0;
            return new BigInteger(hashBytes.Reverse().ToArray());
        }
    }

    static BigInteger RandomBigInteger(BigInteger minValue, BigInteger maxValue)
    {
        Random random = new Random();

        byte[] bytes = new byte[maxValue.ToByteArray().Length];
        random.NextBytes(bytes);

        BigInteger randomValue = new BigInteger(bytes);
        randomValue = BigInteger.Abs(randomValue % (maxValue - minValue + 1)) + minValue;

        return randomValue;
    }

    static bool IsProbablePrime(BigInteger source, int certainty)
    {
        if (source == 2 || source == 3)
            return true;

        if (source < 2 || source % 2 == 0)
            return false;

        BigInteger d = source - 1;
        int s = 0;

        while (d % 2 == 0)
        {
            d /= 2;
            s += 1;
        }

        Random random = new Random();

        for (int i = 0; i < certainty; i++)
        {
            BigInteger a = RandomBigInteger(2, source - 2);

            BigInteger x = BigInteger.ModPow(a, d, source);
            if (x == 1 || x == source - 1)
                continue;

            for (int r = 1; r < s; r++)
            {
                x = BigInteger.ModPow(x, 2, source);
                if (x == 1)
                    return false;
                if (x == source - 1)
                    break;
            }

            if (x != source - 1)
                return false;
        }

        return true;
    }
    //----------------------------------------------------------------------------------------
    static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger m0 = m;
        BigInteger x0 = 0;
        BigInteger x1 = 1;
        if (m == 1)
            return 0;

        while (a > 1)
        {
            BigInteger q = a / m;
            BigInteger t = m;
            m = a % m;
            a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }

        if (x1 < 0)
            x1 += m0;

        return x1;
    }

    static BigInteger GenerateProbablePrime(int bitSize)
    {
        Random random = new Random();

        BigInteger number = RandomBigInteger(BigInteger.Pow(2, bitSize - 1), BigInteger.Pow(2, bitSize) - 1);

        if (number % 2 == 0)
            number++;

        while (!IsProbablePrime(number, 10))
            number += 2;

        return number;
    }
    static void Main()
    {
        BigInteger primeP, primeQ, generatorG, privateKeyX, publicKeyY;
        GeneratePrimeNumbers(out primeP, out primeQ);
        GenerateGenerator(primeP, primeQ, out generatorG);
        GenerateKeyPair(primeP, primeQ, generatorG, out privateKeyX, out publicKeyY);
        Console.WriteLine("Генератор primeP - ");
        Console.WriteLine(primeP);
        Console.WriteLine("Генератор primeQ - ");
        Console.WriteLine(primeQ);
        string message = "DSA";
        BigInteger[] signature = SignMessage(message, primeP, primeQ, generatorG, privateKeyX);
        bool isValidSignature = VerifySignature(message, signature[0], signature[1], primeP, primeQ, generatorG, publicKeyY);
        Console.WriteLine("повiдомлення- " + message);
        Console.WriteLine("Чи дійсний пiдпис? " + isValidSignature);
    }
}