/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ClientPackage;

import java.net.*;
import java.io.*;
import java.util.Scanner;

public class NetworkChatClient {

    /**
     * @param args the command line arguments
     */
    private static Socket s;
    private static DataInputStream in;
    private static DataOutputStream out;
    
    private static ServerSocket serv;
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.print("Input Port: ");
        int port = Integer.parseInt(sc.nextLine());
        
        ChatClient cl = new ChatClient(port);
        cl.start();
        
    }  
}
