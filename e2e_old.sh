#!/bin/bash

# PDFBox main class and JVM options
main_class="org.apache.pdfbox.tools.PDFBox"

workloads=(./workload/000753 ./workload/000809 ./workload/000817)

extension=".pdf"

jvm_args="--add-opens=java.base/java.lang=ALL-UNNAMED \
--add-opens=java.base/java.util=ALL-UNNAMED \
-XX:StartFlightRecording=name=jfrTestRecording,settings=/Users/yogyagamage/Documents/UdeM/theo/settings.jfc,filename=/Users/yogyagamage/Documents/KTH/theo/prod/pdfbox/app/jfr-report1.jfr \
-javaagent:/Users/yogyagamage/Documents/UdeM/theo/theo-agent/target/theo-agent-1.0-SNAPSHOT-jar-with-dependencies.jar"

pdfbox_jar_loc="/Users/yogyagamage/Documents/KTH/theo/prod/pdfbox/app/target/pdfbox-app-4.0.0-SNAPSHOT.jar"

# Execute PDFBox operations for each workload
for i in "${workloads[@]}"; do
#  echo "Encrypt ${i}${extension}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class encrypt -O 123 -U 123 -i ${i}${extension} -o ${i}-locked${extension}"

  echo "Decrypt ${i}${extension}"
  java $jvm_args -jar "$pdfbox_jar_loc" decrypt \
    -password 123 \
    -i "${i}-locked${extension}" \
    -o "${i}-unlocked${extension}"
#  echo "ExtractText ${i}${extension}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class export:text -password 123 -sort -i ${i}-locked${extension} -o ${i}-from-pdf.txt"
#
#  echo "ExtractXMP ${i}${extension}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class export:xmp -password 123 -i ${i}-locked${extension} -o ${i}-from-pdf.txt"
#
#  echo "ExtractImages ${i}${extension}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class export:images -password 123 -useDirectJPEG -i ${i}-locked${extension}"
#
#  echo "PDFSplit ${i}${extension}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class split -password 123 -split 1 -i ${i}-locked${extension}"
#
#  echo "PDFMerger ${i}${extension}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class merge -i ${i}-unlocked${extension} -o ${i}-merged${extension}"
#
#  echo "Render ${i}${extension}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class render -password 123 -i ${i}-locked${extension}"
#
#  echo "Decode ${i}${extension}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class decode -password 123 ${i}-locked${extension} ${i}-decoded${extension}"
#
#  echo "OverlayPDF ${i}${extension}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class overlay -i ${i}${extension} -default ${overlay_pdf}${extension} -position FOREGROUND -o ${i}-overlaid${extension}"
done

# Process image files
#count=0
#for file in ./workload/*.{png,jpg}; do
#  [ -e "$file" ] || continue
#  if [ "$count" -ge 2 ]; then
#    break
#  fi
#  filename="${file##*/}"
#  i="${filename%.*}"
#  extension="${file##*.}"
#  echo "To pdf from image ${i}.${extension}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class fromimage -i $file -o ${i}-from-image.pdf"
#  count=$((count + 1))
#done
#
## Process TXT to PDF
#for file in "${workloads_txt[@]}"; do
#  [ -e "$file" ] || continue
#  sed -i '1s/^\xEF\xBB\xBF//' "$file"
#  filename="${file##*/}"
#  i="${filename%.*}"
#  extension="${file##*.}"
#  echo "To pdf from txt ${i}.${extension}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class fromtext -i $file -o ${i}-from-text.pdf"
#done
#
## Process form import/export
#for file in "${workloads_form[@]}"; do
#  [ -e "$file" ] || continue
#  filename="${file##*/}"
#  i="${filename%.*}"
#  extension="${file##*.}"
#
#  echo "Extract form data to FDF ${i}.${extension}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class export:fdf -i $file -o ${i}-from-form.fdf"
#
#  echo "Extract form data to XFDF ${i}.${extension}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class export:xfdf -i $file -o ${i}-from-form.xfdf"
#
#  echo "Import form data from FDF ${i}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class import:fdf --data ${i}-from-form.fdf -i $file -o ${i}-from-form-fdf.pdf"
#
#  echo "Import form data from XFDF ${i}"
#  mvn exec:exec -Dexec.executable=java -Dexec.args="$jvm_args -cp %classpath $main_class import:xfdf --data ${i}-from-form.xfdf -i $file -o ${i}-from-form-xfdf.pdf"
#done


#  Print
#  echo "print " ${i}${extension}
#  java -jar ${pdfbox_jar_loc} print -password 123 -i ${i}-locked${extension}
