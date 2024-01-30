using Crypt.Project.PasswordHashes;

Pbkdf2 pbkdf2 = new Pbkdf2();
var password = "vm,lxjvbpshwepimncpsdncklpszÂÀÈÊçÇ";

var hash = pbkdf2.HashToString(password);

Console.WriteLine("Hash: " + hash);

var verify = pbkdf2.Verify(password, hash);
Console.WriteLine("Is Equal?: " + verify);

return 0;