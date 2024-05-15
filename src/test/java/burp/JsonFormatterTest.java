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
    public static final String TEST_BOOK_JSON = "{\"store\":{\"book\":[{\"category\":\"reference\",\"author\":\"Nigel Rees\",\"author.nationality\":\"British\",\"title\":\"Sayings of the Century\",\"price\":8.95},{\"category\":\"fiction\",\"author\":\"Evelyn Waugh\",\"author.nationality\":\"British\",\"title\":\"Sword of Honour\",\"price\":12.99},{\"category\":\"fiction\",\"author\":\"Herman Melville\",\"author.nationality\":\"American\",\"title\":\"Moby Dick\",\"isbn\":\"0-553-21311-3\",\"price\":8.99},{\"category\":\"fiction\",\"author\":\"J. R. R. Tolkien\",\"author.nationality\":\"British\",\"title\":\"The Lord of the Rings\",\"isbn\":\"0-395-19395-8\",\"price\":22.99}],\"bicycle\":{\"color\":\"red\",\"price\":19.95}}}";

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
            System.out.println(path.getLine());
        }

        assertEquals(10, lines.size());

        PathTuple line4 = lines.get(4);
        assertEquals("      \"id\" : \"6\",", line4.getLine());
        assertEquals("$[*].id", line4.getPath());

        PathTuple line9 = lines.get(9);
        assertEquals("]", line9.getLine());

    }

    @Test
    public void testLinesWithColon() {
        List<PathTuple> lines = myFormatter.getLines();

        PathTuple line6 = lines.get(6);
        assertEquals("      \"error\" : \"403::Restricted channel\",", line6.getLine());
        assertEquals("$[*].error", line6.getPath());
    }

    @Test
    public void testBookLines() {
        List<PathTuple> lines = myBookFormatter.getLines();

        //visual sanity check
        for (PathTuple path : lines) {
            System.out.println(path.getLine());
        }

        assertEquals(40, lines.size());

        PathTuple line4 = lines.get(4);
        assertEquals("            \"category\" : \"reference\",", line4.getLine());
        assertEquals("$.store.book[*].category", line4.getPath());

        PathTuple line6 = lines.get(6);
        assertEquals("$.store.book[*].['author.nationality']", line6.getPath());

        PathTuple line39 = lines.get(39);
        assertEquals("}", line39.getLine());

    }

}
