package io.openinstall.sdk;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

/* JADX INFO: loaded from: classes3.dex */
public class bp {
    public static void a(File file) {
        try {
            File parentFile = file.getParentFile();
            if (parentFile != null && !parentFile.exists()) {
                parentFile.mkdirs();
            }
            file.createNewFile();
        } catch (Exception e) {
        }
    }

    public static void a(File file, String str, boolean z) throws Throwable {
        a(file, str, false, z);
    }

    public static void a(File file, String str, boolean z, boolean z2) throws Throwable {
        FileWriter fileWriter;
        BufferedWriter bufferedWriter;
        a(file);
        BufferedWriter bufferedWriter2 = null;
        try {
            try {
                fileWriter = new FileWriter(file, z2);
                try {
                    bufferedWriter = new BufferedWriter(fileWriter);
                } catch (IOException e) {
                } catch (Throwable th) {
                    th = th;
                }
                try {
                    bufferedWriter.write(str);
                    if (z) {
                        bufferedWriter.newLine();
                    }
                    bufferedWriter.flush();
                    bufferedWriter.close();
                } catch (IOException e2) {
                    bufferedWriter2 = bufferedWriter;
                    if (bufferedWriter2 != null) {
                        bufferedWriter2.close();
                    }
                    if (fileWriter == null) {
                        return;
                    }
                } catch (Throwable th2) {
                    th = th2;
                    bufferedWriter2 = bufferedWriter;
                    if (bufferedWriter2 != null) {
                        try {
                            bufferedWriter2.close();
                        } catch (IOException e3) {
                            throw th;
                        }
                    }
                    if (fileWriter != null) {
                        fileWriter.close();
                    }
                    throw th;
                }
            } catch (IOException e4) {
                return;
            }
        } catch (IOException e5) {
            fileWriter = null;
        } catch (Throwable th3) {
            th = th3;
            fileWriter = null;
        }
        fileWriter.close();
    }

    public static String b(File file) throws Throwable {
        BufferedReader bufferedReader;
        StringBuilder sb = new StringBuilder();
        FileReader fileReader = null;
        try {
            try {
                FileReader fileReader2 = new FileReader(file);
                try {
                    bufferedReader = new BufferedReader(fileReader2);
                    while (true) {
                        try {
                            String line = bufferedReader.readLine();
                            if (line == null) {
                                break;
                            }
                            sb.append(line);
                        } catch (IOException e) {
                            fileReader = fileReader2;
                            if (fileReader != null) {
                                fileReader.close();
                            }
                            if (bufferedReader != null) {
                            }
                            return sb.toString();
                        } catch (Throwable th) {
                            th = th;
                            fileReader = fileReader2;
                            if (fileReader != null) {
                                try {
                                    fileReader.close();
                                } catch (IOException e2) {
                                    throw th;
                                }
                            }
                            if (bufferedReader != null) {
                                bufferedReader.close();
                            }
                            throw th;
                        }
                    }
                    fileReader2.close();
                } catch (IOException e3) {
                    bufferedReader = null;
                } catch (Throwable th2) {
                    th = th2;
                    bufferedReader = null;
                }
            } catch (IOException e4) {
            }
        } catch (IOException e5) {
            bufferedReader = null;
        } catch (Throwable th3) {
            th = th3;
            bufferedReader = null;
        }
        bufferedReader.close();
        return sb.toString();
    }
}
