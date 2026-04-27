package im.uwrkaxlmjj.messenger;

/* JADX INFO: loaded from: classes2.dex */
public class SecureDocumentKey {
    public byte[] file_iv;
    public byte[] file_key;

    public SecureDocumentKey(byte[] key, byte[] iv) {
        this.file_key = key;
        this.file_iv = iv;
    }
}
