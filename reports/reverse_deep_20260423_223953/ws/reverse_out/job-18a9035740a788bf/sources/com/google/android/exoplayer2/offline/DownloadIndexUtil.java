package com.google.android.exoplayer2.offline;

import com.google.android.exoplayer2.util.Assertions;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;

/* JADX INFO: loaded from: classes2.dex */
public final class DownloadIndexUtil {

    public interface DownloadIdProvider {
        String getId(DownloadAction downloadAction);
    }

    private DownloadIndexUtil() {
    }

    public static void upgradeActionFile(ActionFile actionFile, DownloadIndex downloadIndex, DownloadIdProvider downloadIdProvider) throws IOException {
        if (downloadIdProvider == null) {
            downloadIdProvider = new DownloadIdProvider() { // from class: com.google.android.exoplayer2.offline.-$$Lambda$DownloadIndexUtil$Py1lIUrgVBjWZAWCVofL31wM7XI
                @Override // com.google.android.exoplayer2.offline.DownloadIndexUtil.DownloadIdProvider
                public final String getId(DownloadAction downloadAction) {
                    return downloadAction.id;
                }
            };
        }
        for (DownloadAction action : actionFile.load()) {
            addAction(downloadIndex, downloadIdProvider.getId(action), action);
        }
    }

    public static void addAction(DownloadIndex downloadIndex, String id, DownloadAction action) {
        DownloadState downloadState;
        DownloadState downloadState2 = downloadIndex.getDownloadState(id != null ? id : action.id);
        if (downloadState2 != null) {
            downloadState = merge(downloadState2, action);
        } else {
            downloadState = convert(action);
        }
        downloadIndex.putDownloadState(downloadState);
    }

    private static DownloadState merge(DownloadState downloadState, DownloadAction action) {
        int newState;
        Assertions.checkArgument(action.type.equals(downloadState.type));
        if (action.isRemoveAction) {
            newState = 5;
        } else {
            int newState2 = downloadState.state;
            if (newState2 == 5 || downloadState.state == 7) {
                newState = 7;
            } else if (downloadState.state == 1) {
                newState = 1;
            } else {
                newState = 0;
            }
        }
        HashSet<StreamKey> keys = new HashSet<>(action.keys);
        Collections.addAll(keys, downloadState.streamKeys);
        StreamKey[] newKeys = (StreamKey[]) keys.toArray(new StreamKey[0]);
        return new DownloadState(downloadState.id, downloadState.type, action.uri, action.customCacheKey, newState, -1.0f, downloadState.downloadedBytes, -1L, downloadState.failureReason, downloadState.stopFlags, downloadState.startTimeMs, downloadState.updateTimeMs, newKeys, action.data);
    }

    private static DownloadState convert(DownloadAction action) {
        long currentTimeMs = System.currentTimeMillis();
        return new DownloadState(action.id, action.type, action.uri, action.customCacheKey, action.isRemoveAction ? 5 : 0, -1.0f, 0L, -1L, 0, 0, currentTimeMs, currentTimeMs, (StreamKey[]) action.keys.toArray(new StreamKey[0]), action.data);
    }
}
