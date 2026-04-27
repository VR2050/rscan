package com.blankj.utilcode.util;

import android.util.Log;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/* JADX INFO: loaded from: classes.dex */
public final class ZipUtils {
    private static final int BUFFER_LEN = 8192;

    private ZipUtils() {
        throw new UnsupportedOperationException("u can't instantiate me...");
    }

    public static boolean zipFiles(Collection<String> srcFiles, String zipFilePath) throws IOException {
        return zipFiles(srcFiles, zipFilePath, (String) null);
    }

    public static boolean zipFiles(Collection<String> srcFilePaths, String zipFilePath, String comment) throws IOException {
        if (srcFilePaths == null || zipFilePath == null) {
            return false;
        }
        ZipOutputStream zos = null;
        try {
            zos = new ZipOutputStream(new FileOutputStream(zipFilePath));
            for (String srcFile : srcFilePaths) {
                if (!zipFile(getFileByPath(srcFile), "", zos, comment)) {
                    zos.finish();
                    zos.close();
                    return false;
                }
            }
            zos.finish();
            zos.close();
            return true;
        } catch (Throwable th) {
            if (zos != null) {
                zos.finish();
                zos.close();
            }
            throw th;
        }
    }

    public static boolean zipFiles(Collection<File> srcFiles, File zipFile) throws IOException {
        return zipFiles(srcFiles, zipFile, (String) null);
    }

    public static boolean zipFiles(Collection<File> srcFiles, File zipFile, String comment) throws IOException {
        if (srcFiles == null || zipFile == null) {
            return false;
        }
        ZipOutputStream zos = null;
        try {
            zos = new ZipOutputStream(new FileOutputStream(zipFile));
            for (File srcFile : srcFiles) {
                if (!zipFile(srcFile, "", zos, comment)) {
                    zos.finish();
                    zos.close();
                    return false;
                }
            }
            zos.finish();
            zos.close();
            return true;
        } catch (Throwable th) {
            if (zos != null) {
                zos.finish();
                zos.close();
            }
            throw th;
        }
    }

    public static boolean zipFile(String srcFilePath, String zipFilePath) throws IOException {
        return zipFile(getFileByPath(srcFilePath), getFileByPath(zipFilePath), (String) null);
    }

    public static boolean zipFile(String srcFilePath, String zipFilePath, String comment) throws IOException {
        return zipFile(getFileByPath(srcFilePath), getFileByPath(zipFilePath), comment);
    }

    public static boolean zipFile(File srcFile, File zipFile) throws IOException {
        return zipFile(srcFile, zipFile, (String) null);
    }

    public static boolean zipFile(File srcFile, File zipFile, String comment) throws IOException {
        if (srcFile == null || zipFile == null) {
            return false;
        }
        ZipOutputStream zos = null;
        try {
            zos = new ZipOutputStream(new FileOutputStream(zipFile));
            boolean zZipFile = zipFile(srcFile, "", zos, comment);
            zos.close();
            return zZipFile;
        } catch (Throwable th) {
            if (zos != null) {
                zos.close();
            }
            throw th;
        }
    }

    private static boolean zipFile(File srcFile, String rootPath, ZipOutputStream zos, String comment) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(rootPath);
        sb.append(isSpace(rootPath) ? "" : File.separator);
        sb.append(srcFile.getName());
        String rootPath2 = sb.toString();
        if (srcFile.isDirectory()) {
            File[] fileList = srcFile.listFiles();
            if (fileList == null || fileList.length <= 0) {
                ZipEntry entry = new ZipEntry(rootPath2 + '/');
                entry.setComment(comment);
                zos.putNextEntry(entry);
                zos.closeEntry();
                return true;
            }
            for (File file : fileList) {
                if (!zipFile(file, rootPath2, zos, comment)) {
                    return false;
                }
            }
            return true;
        }
        InputStream is = null;
        try {
            is = new BufferedInputStream(new FileInputStream(srcFile));
            ZipEntry entry2 = new ZipEntry(rootPath2);
            entry2.setComment(comment);
            zos.putNextEntry(entry2);
            byte[] buffer = new byte[8192];
            while (true) {
                int len = is.read(buffer, 0, 8192);
                if (len != -1) {
                    zos.write(buffer, 0, len);
                } else {
                    zos.closeEntry();
                    is.close();
                    return true;
                }
            }
        } catch (Throwable th) {
            if (is != null) {
                is.close();
            }
            throw th;
        }
    }

    public static List<File> unzipFile(String zipFilePath, String destDirPath) throws IOException {
        return unzipFileByKeyword(zipFilePath, destDirPath, (String) null);
    }

    public static List<File> unzipFile(File zipFile, File destDir) throws IOException {
        return unzipFileByKeyword(zipFile, destDir, (String) null);
    }

    public static List<File> unzipFileByKeyword(String zipFilePath, String destDirPath, String keyword) throws IOException {
        return unzipFileByKeyword(getFileByPath(zipFilePath), getFileByPath(destDirPath), keyword);
    }

    public static List<File> unzipFileByKeyword(File zipFile, File destDir, String keyword) throws IOException {
        if (zipFile == null || destDir == null) {
            return null;
        }
        List<File> files = new ArrayList<>();
        ZipFile zip = new ZipFile(zipFile);
        Enumeration<?> entries = zip.entries();
        try {
            if (isSpace(keyword)) {
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String entryName = entry.getName().replace("\\", "/");
                    if (entryName.contains("../")) {
                        Log.e("ZipUtils", "entryName: " + entryName + " is dangerous!");
                    } else if (!unzipChildFile(destDir, files, zip, entry, entryName)) {
                        return files;
                    }
                }
            } else {
                while (entries.hasMoreElements()) {
                    ZipEntry entry2 = entries.nextElement();
                    String entryName2 = entry2.getName().replace("\\", "/");
                    if (entryName2.contains("../")) {
                        Log.e("ZipUtils", "entryName: " + entryName2 + " is dangerous!");
                    } else if (entryName2.contains(keyword) && !unzipChildFile(destDir, files, zip, entry2, entryName2)) {
                        return files;
                    }
                }
            }
            return files;
        } finally {
            zip.close();
        }
    }

    private static boolean unzipChildFile(File destDir, List<File> files, ZipFile zip, ZipEntry entry, String name) throws IOException {
        File file = new File(destDir, name);
        files.add(file);
        if (entry.isDirectory()) {
            return createOrExistsDir(file);
        }
        if (!createOrExistsFile(file)) {
            return false;
        }
        InputStream in = null;
        OutputStream out = null;
        try {
            in = new BufferedInputStream(zip.getInputStream(entry));
            out = new BufferedOutputStream(new FileOutputStream(file));
            byte[] buffer = new byte[8192];
            while (true) {
                int len = in.read(buffer);
                if (len != -1) {
                    out.write(buffer, 0, len);
                } else {
                    in.close();
                    out.close();
                    return true;
                }
            }
        } catch (Throwable th) {
            if (in != null) {
                in.close();
            }
            if (out != null) {
                out.close();
            }
            throw th;
        }
    }

    public static List<String> getFilesPath(String zipFilePath) throws IOException {
        return getFilesPath(getFileByPath(zipFilePath));
    }

    public static List<String> getFilesPath(File zipFile) throws IOException {
        if (zipFile == null) {
            return null;
        }
        List<String> paths = new ArrayList<>();
        ZipFile zip = new ZipFile(zipFile);
        Enumeration<?> entries = zip.entries();
        while (entries.hasMoreElements()) {
            String entryName = entries.nextElement().getName().replace("\\", "/");
            if (entryName.contains("../")) {
                Log.e("ZipUtils", "entryName: " + entryName + " is dangerous!");
                paths.add(entryName);
            } else {
                paths.add(entryName);
            }
        }
        zip.close();
        return paths;
    }

    public static List<String> getComments(String zipFilePath) throws IOException {
        return getComments(getFileByPath(zipFilePath));
    }

    public static List<String> getComments(File zipFile) throws IOException {
        if (zipFile == null) {
            return null;
        }
        List<String> comments = new ArrayList<>();
        ZipFile zip = new ZipFile(zipFile);
        Enumeration<?> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            comments.add(entry.getComment());
        }
        zip.close();
        return comments;
    }

    private static boolean createOrExistsDir(File file) {
        return file != null && (!file.exists() ? !file.mkdirs() : !file.isDirectory());
    }

    private static boolean createOrExistsFile(File file) {
        if (file == null) {
            return false;
        }
        if (file.exists()) {
            return file.isFile();
        }
        if (!createOrExistsDir(file.getParentFile())) {
            return false;
        }
        try {
            return file.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    private static File getFileByPath(String filePath) {
        if (isSpace(filePath)) {
            return null;
        }
        return new File(filePath);
    }

    private static boolean isSpace(String s) {
        if (s == null) {
            return true;
        }
        int len = s.length();
        for (int i = 0; i < len; i++) {
            if (!Character.isWhitespace(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}
