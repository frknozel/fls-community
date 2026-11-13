import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.channels.FileChannel;
import java.util.Base64;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import tr.gov.tubitak.uekae.esya.api.common.util.LicenseUtil;
import tr.gov.tubitak.uekae.esya.api.infra.tsclient.*;
import tr.gov.tubitak.uekae.esya.api.crypto.alg.DigestAlg;

/** Calls the official KamuSM timestamp client. Secrets are read only from stdin. */
public final class FlsTsaBridge {
 static byte[] hex(String s) {return java.util.HexFormat.of().parseHex(s);}
 public static void main(String[] args) {
  PrintStream result=System.out;
  System.setOut(new PrintStream(OutputStream.nullOutputStream()));
  System.setErr(new PrintStream(OutputStream.nullOutputStream()));
  try {
   Path vendor=Path.of(args[0]);
   try(InputStream in=Files.newInputStream(vendor.resolve("client-license.xml"))){
    if(!LicenseUtil.setLicenseXml(in))throw new IllegalStateException("client_license_invalid");
   }
   if(args.length==2 && args[1].equals("selfcheck")){result.println("{\"official_client_license\":true}");return;}
   BufferedReader input=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));
   String mode=input.readLine(),url=input.readLine(),user=input.readLine();
   final char[] proxyToken=input.readLine().toCharArray();
   Authenticator.setDefault(new Authenticator(){protected PasswordAuthentication getPasswordAuthentication(){return getRequestorType()==RequestorType.PROXY?new PasswordAuthentication("fls",proxyToken):null;}});
   char[] password=new String(Base64.getDecoder().decode(input.readLine()),StandardCharsets.UTF_8).toCharArray();
   TSSettings settings=new TSSettings(url,Integer.parseInt(user),password,DigestAlg.SHA256);settings.setConnectionTimeOut(30000);
   TSClient client=new TSClient();
   if(mode.equals("balance")){long credit=client.requestRemainingCredit(settings);result.println("{\"credit\":"+credit+"}");return;}
   if(!mode.equals("stamp"))throw new IllegalArgumentException("mode_invalid");
   byte[] digest=hex(input.readLine()),nonce=hex(input.readLine());settings.setRequestNonce(nonce);
   var response=client.timestamp(digest,settings);byte[] encoded=response.getEncoded();
   Path target=Path.of(args[1]),temp=target.resolveSibling(target.getFileName()+".tmp");
   try(FileChannel file=FileChannel.open(temp,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){java.nio.ByteBuffer bytes=java.nio.ByteBuffer.wrap(encoded);while(bytes.hasRemaining())file.write(bytes);file.force(true);}
   Files.move(temp,target,StandardCopyOption.ATOMIC_MOVE);
   try(FileChannel directory=FileChannel.open(target.getParent(),StandardOpenOption.READ)){directory.force(true);}
   java.util.Arrays.fill(password,'\0');result.println("{\"response_saved\":true}");
  }catch(Throwable e){result.println("{\"error\":\"official_client_failed\"}");System.exit(1);}
 }
}
