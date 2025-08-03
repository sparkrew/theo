import org.apache.pdfbox.tools.PDFBox;
import java.io.File;
import java.util.Arrays;
import java.util.List;

public class RunAllOperations {

    public static void main(String[] args) throws Exception {
        System.out.println("Starting all PDF operations...");

        String extension = ".pdf";
        String overlayPdf = "/Users/yogyagamage/Documents/UdeM/theo/workload/000142";

        List<String> workloads = Arrays.asList(
                "/Users/yogyagamage/Documents/UdeM/theo/workload/000753"
        );

        List<String> workloadsForm = Arrays.asList(
                "/Users/yogyagamage/Documents/UdeM/theo/workload/FillFormField.pdf"
        );

        List<String> workloadsTxt = Arrays.asList(
                "/Users/yogyagamage/Documents/UdeM/theo/workload/000753-from-pdf.txt"
        );

        for (String i : workloads) {
            exec("encrypt", "-O", "123", "-U", "123", "-i", i + extension, "-o", i + "-locked" + extension);
            exec("decrypt", "-password", "123", "-i", i + "-locked" + extension, "-o", i + "-unlocked" + extension);
            exec("export:text", "-password", "123", "-sort", "-i", i + "-locked" + extension, "-o", i + "-from-pdf.txt");
            exec("export:xmp", "-password", "123", "-i", i + "-locked" + extension, "-o", i + "-from-pdf.txt");
            exec("export:images", "-password", "123", "-useDirectJPEG", "-i", i + "-locked" + extension);
            exec("split", "-password", "123", "-split", "1", "-i", i + "-locked" + extension);
            exec("merge", "-i", i + "-unlocked" + extension, "-o", i + "-merged" + extension);
            exec("render", "-password", "123", "-i", i + "-locked" + extension);
            exec("decode", "-password", "123", i + "-locked" + extension, i + "-decoded" + extension);
            exec("overlay", "-i", i + extension, "-default", overlayPdf + extension, "-position", "FOREGROUND", "-o", i + "-overlaid" + extension);
        }

        // From image to PDF
        File imageDir = new File("./workload");
        File[] imageFiles = imageDir.listFiles((dir, name) -> name.endsWith(".jpg") || name.endsWith(".png"));
        if (imageFiles != null) {
            for (int count = 0; count < Math.min(2, imageFiles.length); count++) {
                File file = imageFiles[count];
                String fileName = file.getName();
                String i = fileName.substring(0, fileName.lastIndexOf('.'));
                exec("fromimage", "-i", file.getAbsolutePath(), "-o", i + "-from-image.pdf");
            }
        }

        // TXT to PDF
        for (String file : workloadsTxt) {
            String fileName = new File(file).getName();
            String i = fileName.substring(0, fileName.lastIndexOf('.'));
            exec("fromtext", "-i", file, "-o", i + "-from-text.pdf");
        }

        // Forms
        for (String file : workloadsForm) {
            String fileName = new File(file).getName();
            String i = fileName.substring(0, fileName.lastIndexOf('.'));
            exec("export:fdf", "-i", file, "-o", i + "-from-form.fdf");
            exec("export:xfdf", "-i", file, "-o", i + "-from-form.xfdf");
//            exec("import:fdf", "--data", i + "-from-form.fdf", "-i", file, "-o", i + "-from-form-fdf.pdf");
            exec("import:xfdf", "--data", i + "-from-form.xfdf", "-i", file, "-o", i + "-from-form-xfdf.pdf");
        }

        System.out.println("All operations completed.");
    }

    private static void exec(String... args) throws Exception {
        System.out.println("Running: " + String.join(" ", args));
        PDFBox.main(args);
    }
}
