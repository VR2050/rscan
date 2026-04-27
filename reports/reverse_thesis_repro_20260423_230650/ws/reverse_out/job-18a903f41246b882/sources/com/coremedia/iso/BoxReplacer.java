package com.coremedia.iso;

import com.coremedia.iso.boxes.Box;
import com.googlecode.mp4parser.FileDataSourceImpl;
import com.googlecode.mp4parser.util.Path;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public class BoxReplacer {
    static final /* synthetic */ boolean $assertionsDisabled = false;

    public static void replace(Map<String, Box> replacements, File file) throws IOException {
        IsoFile isoFile = new IsoFile(new FileDataSourceImpl(new RandomAccessFile(file, "r").getChannel()));
        Map<String, Box> replacementSanitised = new HashMap<>();
        Map<String, Long> positions = new HashMap<>();
        for (Map.Entry<String, Box> e : replacements.entrySet()) {
            Box b = Path.getPath(isoFile, e.getKey());
            replacementSanitised.put(Path.createPath(b), e.getValue());
            positions.put(Path.createPath(b), Long.valueOf(b.getOffset()));
        }
        isoFile.close();
        FileChannel fileChannel = new RandomAccessFile(file, "rw").getChannel();
        for (String path : replacementSanitised.keySet()) {
            Box b2 = replacementSanitised.get(path);
            long pos = positions.get(path).longValue();
            fileChannel.position(pos);
            b2.getBox(fileChannel);
        }
        fileChannel.close();
    }
}
