package com.google.android.exoplayer2.offline;

import com.google.android.exoplayer2.util.AtomicFile;
import com.google.android.exoplayer2.util.Util;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

/* JADX INFO: loaded from: classes2.dex */
public final class ActionFile {
    static final int VERSION = 0;
    private final File actionFile;
    private final AtomicFile atomicFile;

    public ActionFile(File actionFile) {
        this.actionFile = actionFile;
        this.atomicFile = new AtomicFile(actionFile);
    }

    public DownloadAction[] load() throws IOException {
        if (!this.actionFile.exists()) {
            return new DownloadAction[0];
        }
        InputStream inputStream = null;
        try {
            inputStream = this.atomicFile.openRead();
            DataInputStream dataInputStream = new DataInputStream(inputStream);
            int version = dataInputStream.readInt();
            if (version > 0) {
                throw new IOException("Unsupported action file version: " + version);
            }
            int actionCount = dataInputStream.readInt();
            DownloadAction[] actions = new DownloadAction[actionCount];
            for (int i = 0; i < actionCount; i++) {
                actions[i] = DownloadAction.deserializeFromStream(dataInputStream);
            }
            return actions;
        } finally {
            Util.closeQuietly(inputStream);
        }
    }

    public void store(DownloadAction... downloadActions) throws IOException {
        DataOutputStream output = null;
        try {
            output = new DataOutputStream(this.atomicFile.startWrite());
            output.writeInt(0);
            output.writeInt(downloadActions.length);
            for (DownloadAction action : downloadActions) {
                action.serializeToStream(output);
            }
            this.atomicFile.endWrite(output);
            output = null;
        } finally {
            Util.closeQuietly(output);
        }
    }
}
