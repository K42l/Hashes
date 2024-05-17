//using Crypt.Project.PasswordHashes;
//
//Pbkdf2Hashing pbkdf2 = new Pbkdf2Hashing();
//var password = "vm,lxjvbpshwepimncpsdncklpszÂÀÈÊçÇ";
//
//var hash = pbkdf2.HashToString(password);
//
//Console.WriteLine("Hash: " + hash);
//
//var verify = pbkdf2.Verify(password, hash);
//Console.WriteLine("Is Equal?: " + verify);
//
//return 0;


using Crypt.Project.Hahses;


Md5Hash md5Hash = new Md5Hash();

var teste = "A-1-151515-0";

var hash = md5Hash.CreateHashFromString(teste);


Console.Write(hash);
Console.WriteLine(hash.Length);


return 0;