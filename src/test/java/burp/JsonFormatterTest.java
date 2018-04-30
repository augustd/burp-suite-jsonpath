package burp;

import burp.JsonFormatter.PathTuple;
import java.util.List;
import static junit.framework.Assert.assertEquals;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author adetlefsen
 */
public class JsonFormatterTest {
    
    public static final String TEST_JSON = "[{\"clientId\":\"jo715kl631pr9yfe1vcukvkeqedz2\",\"channel\":\"/meta/subscribe\",\"id\":\"6\",\"subscription\":\"/s/notifications/readstate\",\"error\":\"403::Restricted channel\",\"successful\":false}]";
    public static final String TEST_BOOK_JSON = "{\"store\":{\"book\":[{\"category\":\"reference\",\"author\":\"Nigel Rees\",\"title\":\"Sayings of the Century\",\"price\":8.95},{\"category\":\"fiction\",\"author\":\"Evelyn Waugh\",\"title\":\"Sword of Honour\",\"price\":12.99},{\"category\":\"fiction\",\"author\":\"Herman Melville\",\"title\":\"Moby Dick\",\"isbn\":\"0-553-21311-3\",\"price\":8.99},{\"category\":\"fiction\",\"author\":\"J. R. R. Tolkien\",\"title\":\"The Lord of the Rings\",\"isbn\":\"0-395-19395-8\",\"price\":22.99}],\"bicycle\":{\"color\":\"red\",\"price\":19.95}}}";
    
    static JsonFormatter myFormatter;
    private static JsonFormatter myBookFormatter;
    
    @BeforeClass
    public static void setUpClass() throws Exception {
        myFormatter = new burp.JsonFormatter(TEST_JSON);
        myBookFormatter = new burp.JsonFormatter(TEST_BOOK_JSON);
    }
    
    
    @Test
    public void testPrettyPrint() {
        String their = com.jayway.jsonpath.internal.JsonFormatter.prettyPrint(TEST_JSON);
        System.out.println("EXPECTED ----------------");
        System.out.println(their);

        //JsonFormatter myFormatter = new burp.JsonFormatter(TEST_JSON);
        String my = myFormatter.prettyPrint();
        System.out.println("GOT ---------------------");
        System.out.println(my);
        
        assertEquals(their, my);
    }
    
    @Test
    public void testBookPrettyPrint() {
        String their = com.jayway.jsonpath.internal.JsonFormatter.prettyPrint(TEST_BOOK_JSON);
        System.out.println("EXPECTED ----------------");
        System.out.println(their);

        //JsonFormatter myFormatter = new burp.JsonFormatter(TEST_JSON);
        String my = myBookFormatter.prettyPrint();
        System.out.println("GOT ---------------------");
        System.out.println(my);
        
        assertEquals(their, my);
    }
    
    @Test
    public void testLines() {
        List<PathTuple> lines = myFormatter.getLines();

        //visual sanity check
        for (PathTuple path : lines) {
            System.out.println(path.line);
        }

        assertEquals(10, lines.size());

        PathTuple line4 = lines.get(4);
        assertEquals("      \"id\" : \"6\",", line4.line);
        assertEquals("$[*].id", line4.path);
        
        PathTuple line9 = lines.get(9);
        assertEquals("]", line9.line);
        
    }
    
    @Test
    public void testLinesWithColon() {
        List<PathTuple> lines = myFormatter.getLines();

        PathTuple line6 = lines.get(6);
        assertEquals("      \"error\" : \"403::Restricted channel\",", line6.line);
        assertEquals("$[*].error", line6.path);
    }
    
    @Test
    public void testBookLines() {
        List<PathTuple> lines = myBookFormatter.getLines();

        //visual sanity check
        for (PathTuple path : lines) {
            System.out.println(path.line);
        }

        assertEquals(36, lines.size());

        PathTuple line4 = lines.get(4);
        assertEquals("            \"category\" : \"reference\",", line4.line);
        assertEquals("$.store.book[*].category", line4.path);
        
        PathTuple line35 = lines.get(35);
        assertEquals("}", line35.line);
        
    }
    
}
