/**
 * By zlbimproving
 **/

public class Main {
    public static void main(String[] args) {
        SimhashAlgoService simhashAlgoService = new SimhashAlgoService();
        String result = simhashAlgoService.compare("He is a boy", "but she is a girl");
        System.out.println(result);
    }
}
