using Algorithms;
using Algorithms.Common.DataTransferObjects;
using Algorithms.Common.Enums;
// See https://aka.ms/new-console-template for more information
/*Noekeon A1 = new Noekeon();
A1.Initial("b");*/

/*Piccolo A2 = new Piccolo();
A2.Initial("p");*/
/*Present A3=new Present();
A3.Initial("p1");*/

/*Mysterion A4=new Mysterion();
A4.Initial("p2");*/
/*Pride A5=new Pride();
A5.Initial("p3");*/

// byte[] data = new byte[]{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};

// RC512 rc5 = new RC512("asdfasdfasdfasdf");

// byte[] encryptedData = rc5.Encrypt(data);
// byte[] decryptedData = rc5.Decrypt(encryptedData);

// Console.WriteLine("Data:           " + BitConverter.ToString(data));
// Console.WriteLine("Encrypted Data: " + BitConverter.ToString(encryptedData));
// Console.WriteLine("Decrypted Data: " + BitConverter.ToString(decryptedData));


// Rectangle rectangle = new Rectangle("");
// rectangle.test();

InputDto inputDto = new InputDto();
inputDto.Key = "asdfasdfasdfasdf";
inputDto.Data = "Hello world 123 ! Hello world 123 123 123 .";
inputDto.InputTypes = DataTypes.String;
inputDto.OutputTypes = DataTypes.String;

// Prince prince = new Prince(inputDto);
// Robin rr = new Robin(inputDto);
// RoadRunneR rr = new RoadRunneR(inputDto);
RC512 rc5 = new RC512(inputDto);

// ushort[] Key = new ushort[] { 0xffff, 0xffff, 0xffff, 0xffff, 0xaaaa };
// inputDto.Key = Rectangle.uShortArrayToString(Key);
// inputDto.Data = Rectangle.uShortArrayToString(new ushort[] { 0xabca, 0x4611, 0xffff, 0x1234});
// Rectangle rectangle = new Rectangle(inputDto);


// Console.WriteLine(11.ToString("X"));
// Console.WriteLine(int.Parse("B", System.Globalization.NumberStyles.HexNumber));
// //Console.WriteLine(new Mysterion("deneme", "").ini);
// Console.ReadLine();
