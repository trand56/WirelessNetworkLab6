/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networkchatserver;

/**
 *
 * @author tsuoi
 */

import java.util.Scanner;

public class NetworkChatServer {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        Scanner sc = new Scanner(System.in);
        System.out.print("Input Port: ");
        int port = Integer.parseInt(sc.nextLine());

        ChatServer serv = new ChatServer(port);
        serv.start();
    }
    
}
