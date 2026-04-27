package im.uwrkaxlmjj.ui.utils.translate.utils;

import android.text.TextUtils;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/* JADX INFO: loaded from: classes5.dex */
public class AudioFileUtils {
    public static final String SAVE_AUDIO_FOLDER = "/audio_cache";

    public static String getAudioEditStorageDirectory() {
        return ApplicationLoader.applicationContext.getCacheDir().getAbsolutePath() + SAVE_AUDIO_FOLDER;
    }

    public static boolean confirmFolderExist(String folderPath) {
        File file = new File(folderPath);
        if (!file.exists()) {
            return file.mkdirs();
        }
        return false;
    }

    public static void copyFile(String srcPath, String destPath) {
        FileInputStream fis = null;
        FileOutputStream fos = null;
        try {
            if (!TextUtils.isEmpty(srcPath) && !TextUtils.isEmpty(destPath) && !TextUtils.equals(srcPath, destPath)) {
                FileLog.e("-----------" + new File(destPath).exists());
                File destFile = new File(destPath);
                if (!destFile.getParentFile().exists()) {
                    FileLog.e("-----------" + new File(destPath).exists());
                    destFile.getParentFile().mkdirs();
                }
                new File(destPath).delete();
                String tempPath = srcPath + ".temp";
                File oldfile = new File(srcPath);
                if (oldfile.exists()) {
                    fis = new FileInputStream(srcPath);
                    fos = new FileOutputStream(tempPath);
                    byte[] buffer = new byte[1024];
                    while (true) {
                        int length = fis.read(buffer);
                        if (length == -1) {
                            break;
                        } else {
                            fos.write(buffer, 0, length);
                        }
                    }
                }
                fos.close();
                fis.close();
                FileLog.e("-----------" + new File(tempPath).renameTo(new File(destPath)));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void deleteFile(File file) {
        File[] files;
        if (file != null && file.exists()) {
            if (file.isDirectory() && (files = file.listFiles()) != null) {
                for (File childFile : files) {
                    deleteFile(childFile);
                }
            }
            deleteFileSafely(file);
        }
    }

    public static boolean checkFileExist(String filePath) {
        if (TextUtils.isEmpty(filePath)) {
            return false;
        }
        return new File(filePath).exists();
    }

    public static boolean deleteFileSafely(File file) {
        if (file != null) {
            String tmpPath = file.getParent() + File.separator + System.currentTimeMillis();
            File tmp = new File(tmpPath);
            file.renameTo(tmp);
            return tmp.delete();
        }
        return false;
    }

    public static void saveFile(String url, String content) {
        saveFile(url, content, true, false);
    }

    public static void saveFile(String url, String content, boolean cover, boolean append) {
        FileOutputStream out = null;
        File file = new File(url);
        try {
            if (file.exists()) {
                if (cover) {
                    file.delete();
                    file.createNewFile();
                }
            } else {
                file.createNewFile();
            }
            out = new FileOutputStream(file, append);
            out.write(content.getBytes());
            out.close();
            FileLog.e("保存文件" + url + "保存文件成功");
        } catch (Exception e) {
            FileLog.e("保存文件" + url, e);
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
    }

    public static BufferedOutputStream getBufferedOutputStreamFromFile(String fileUrl) {
        try {
            File file = new File(fileUrl);
            if (file.exists()) {
                file.delete();
            }
            file.createNewFile();
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(file));
            return bufferedOutputStream;
        } catch (Exception e) {
            FileLog.e("GetBufferedOutputStreamFromFile异常", e);
            return null;
        }
    }

    public static void renameFile(String oldPath, String newPath) {
        if (!TextUtils.isEmpty(oldPath) && !TextUtils.isEmpty(newPath)) {
            File newFile = new File(newPath);
            if (newFile.exists()) {
                newFile.delete();
            }
            File oldFile = new File(oldPath);
            if (oldFile.exists()) {
                try {
                    oldFile.renameTo(new File(newPath));
                } catch (Exception e) {
                    FileLog.e("删除本地文件失败", e);
                }
            }
        }
    }
}
