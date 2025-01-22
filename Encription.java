import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random ;

public class Encryption implements ActionListener{
        JButton btn, btn1, btn2;
        byte[] skey = new byte[1000];
        String skeyString;
        JPasswordField pass;
        JFrame frm1;

        static byte[] raw, ebyte;
        String inputMessage,encryptedData,decryptedMessage;

        public Encryption(){
        generateSymmetricKey();
        JFrame frm = new JFrame("Security page");
        frm.setLayout(new FlowLayout());
        frm.setSize(500,500);
        frm.setLayout(null);
        JLabel jl1 = new JLabel("Data Security Page :-");
        jl1.setBounds(50,80,130,15);
        frm.add(jl1);
        frm.setVisible(true);


        JLabel jl2 = new JLabel("This will secure your data with password security");
        jl2.setBounds(50,70,300,80);
        frm.add(jl2);

        JLabel jl3 = new JLabel("Click here to encrypt your data");
        jl3.setBounds(100,110,500,200);
        frm.add(jl3);

        btn = new JButton("Enter");
        btn.setBounds(150,230,100,40);
        frm.add(btn);
        btn.addActionListener(this);


        }
          public void actionPerformed(ActionEvent e){
                    if(e.getSource() == btn){
                        frm1 = new JFrame("Encryption page");
                        frm1.setLayout(new FlowLayout());
                        frm1.setSize(400,400);
                        frm1.setVisible(true);

                        JLabel jl2 = new JLabel("This will encrypt your data");
                        jl2.setBounds(50,70,400,40);
                        frm1.add(jl2);
                        frm1.setLayout(null);

                        JLabel jl3 = new JLabel("Enter your password to encrypt and decrpyt data");
                        jl3.setBounds(50,130,250,50);
                        frm1.add(jl3);

                        JLabel jlpass = new JLabel("Password");
                        jlpass.setBounds(50,180,100,30);
                        frm1.add(jlpass);
                        pass = new JPasswordField();
                        pass.setEchoChar('*');
                        pass.setBounds(130,180,100,30);
                        frm1.add(pass);

                        btn1 = new JButton("ENCRYPT");
                        btn1.setBounds(50,230,100,20);
                        frm1.add(btn1);
                        btn1.addActionListener(this);

                        btn2 = new JButton("DECRYPT");
                        btn2.setBounds(190,230,100,20);
                        frm1.add(btn2);
                        btn2.addActionListener(this);
}
                        String v1=pass.getText();
                        if(e.getSource() == btn1){
                            //creating password for encryption
                            //this will open window for encrypting data
                            if ( v1.equals("1234"))
                                try{
                                    inputMessage=JOptionPane.showInputDialog(null,"Enter message to encrypt");
                                    byte[] ibyte = inputMessage.getBytes();
                                    ebyte = encrypt(raw, ibyte);
                                    String encryptedData = new String(ebyte);
                                    System.out.println("Encrypted message "+encryptedData);
                                    JOptionPane.showMessageDialog(null,"Encrypted Data "+"\n"+encryptedData);
                                }
                                catch(Exception e1){
                                    System.out.println(e1);

                                }
                                else{
                                    JOptionPane.showMessageDialog(frm1,"Enter valid password");
                                }

                            }
                            if(e.getSource() == btn2){
                            //creating password for decryption
                            //this will show decrypted data
                            if(v1.equals("4321"))
                                try{
                                   byte[] dbyte= decrypt(raw,ebyte);
                                   String decryptedMessage = new String(dbyte);
                                   JOptionPane.showMessageDialog(null,"Decrypted Data "+"\n"+decryptedMessage);
                               }
                               catch(Exception e2){
                                   System.out.println(e2);
                               }
                               else{
                                   JOptionPane.showMessageDialog(frm1,"Enter valid password");
                               }
                            }

                    }

                                  private static byte[] getRawKey(byte[] seed) throws Exception {
                                    KeyGenerator kgen = KeyGenerator.getInstance("AES");
                                    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
                                    sr.setSeed(seed);
                                    kgen.init(128, sr); // 192 and 256 bits may not be available
                                    SecretKey skey = kgen.generateKey();
                                    raw = skey.getEncoded();
                                    return raw;
                                    }
                                    //code to encrypt data
                                    private static byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
                                    SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
                                    Cipher cipher = Cipher.getInstance("AES");
                                    cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
                                    byte[] encrypted = cipher.doFinal(clear);
                                    return encrypted;
                                    }
                                    //code to decrypt data
                                    private static byte[] decrypt(byte[] raw, byte[] encrypted) throws Exception {
                                    SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
                                    Cipher cipher = Cipher.getInstance("AES");
                                    cipher.init(Cipher.DECRYPT_MODE, skeySpec);
                                    byte[] decrypted = cipher.doFinal(encrypted);
                                    return decrypted;
                                    }


    void generateSymmetricKey() {
    try {
    Random r = new Random();
    int num = r.nextInt(10000);
    String knum = String.valueOf(num);
    byte[] knumb = knum.getBytes();
    skey=getRawKey(knumb);
    skeyString = new String(skey);
    //System.out.println("AES Symmetric key = "+skeyString);
}
catch(Exception e) {
System.out.println(e);
}
}
                public static void main(String srg[]){
                    new Encryption();
            }
}