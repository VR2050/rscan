package im.uwrkaxlmjj.ui.utils.picture;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.utils.DrawableUtils;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.NativeByteBuffer;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PictureUtil {

    public interface CallBack {
        void loadPictureResult(boolean z, byte[] bArr, Bitmap bitmap, String str);
    }

    private static ConnectionsManager getConnectionsManager() {
        return ConnectionsManager.getInstance(UserConfig.selectedAccount);
    }

    public static void loadPictureByFileId(int classGuid, long fileId, long fileHash, int fileSize, final CallBack callBack) {
        int i = fileSize;
        byte[] downloadBytes = new byte[i];
        final int chunkSize = i > 1048576 ? 131072 : 32768;
        int i2 = 0;
        final int count = (i / chunkSize) + (i % chunkSize != 0 ? 1 : 0);
        int index = 0;
        while (index < count) {
            final TLRPC.TL_upload_getFile req = new TLRPC.TL_upload_getFile();
            req.location = new TLRPC.TL_inputDocumentFileLocation();
            req.location.file_reference = new byte[i2];
            req.location.thumb_size = "";
            req.location.access_hash = fileHash;
            req.location.id = fileId;
            req.offset = index * chunkSize;
            if (index == count - 1) {
                req.limit = i - req.offset;
            } else {
                req.limit = chunkSize;
            }
            final int finalIndex = index;
            final byte[] bArr = downloadBytes;
            getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.utils.picture.-$$Lambda$PictureUtil$bL7QSSg_bUzOID_5KI358O1vnsc
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    PictureUtil.lambda$loadPictureByFileId$3(req, bArr, finalIndex, chunkSize, callBack, count, tLObject, tL_error);
                }
            }), classGuid);
            index++;
            i = fileSize;
            downloadBytes = downloadBytes;
            i2 = 0;
        }
    }

    static /* synthetic */ void lambda$loadPictureByFileId$3(TLRPC.TL_upload_getFile req, final byte[] downloadBytes, int finalIndex, int chunkSize, final CallBack callBack, int count, TLObject response, final TLRPC.TL_error error) {
        if (response != null) {
            if (response instanceof TLRPC.TL_upload_file) {
                TLRPC.TL_upload_file upload_file = (TLRPC.TL_upload_file) response;
                if (upload_file.bytes != null) {
                    NativeByteBuffer buffer = upload_file.bytes;
                    try {
                        byte[] array = buffer.readData(req.limit, true);
                        System.arraycopy(array, 0, downloadBytes, finalIndex * chunkSize, array.length);
                    } catch (Exception e) {
                        ToastUtils.show(R.string.LoadPictureFailed);
                        FileLog.e(e);
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.utils.picture.-$$Lambda$PictureUtil$2p06TXsuCxJxnLyfD9sZIyb_Vvs
                            @Override // java.lang.Runnable
                            public final void run() {
                                PictureUtil.lambda$null$0(callBack, e);
                            }
                        });
                    }
                }
            }
            if (finalIndex == count - 1) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.utils.picture.-$$Lambda$PictureUtil$6t-pku79MzwH4Oacl2cdhmtc1Fk
                    @Override // java.lang.Runnable
                    public final void run() {
                        PictureUtil.lambda$null$1(callBack, downloadBytes);
                    }
                });
                return;
            }
            return;
        }
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.utils.picture.-$$Lambda$PictureUtil$QsrJ9ee-8Rnme75T5gtf2rLBZXQ
                @Override // java.lang.Runnable
                public final void run() {
                    PictureUtil.lambda$null$2(callBack, error);
                }
            });
            ToastUtils.show(R.string.LoadPictureFailed);
        }
    }

    static /* synthetic */ void lambda$null$0(CallBack callBack, Exception e) {
        if (callBack != null) {
            callBack.loadPictureResult(false, null, null, e.getMessage());
        }
    }

    static /* synthetic */ void lambda$null$1(CallBack callBack, byte[] downloadBytes) {
        BitmapFactory.Options options = new BitmapFactory.Options();
        if (callBack != null) {
            callBack.loadPictureResult(true, downloadBytes, DrawableUtils.getPicFromBytes(downloadBytes, options), null);
        }
    }

    static /* synthetic */ void lambda$null$2(CallBack callBack, TLRPC.TL_error error) {
        if (callBack != null) {
            callBack.loadPictureResult(false, null, null, error.text);
        }
    }
}
