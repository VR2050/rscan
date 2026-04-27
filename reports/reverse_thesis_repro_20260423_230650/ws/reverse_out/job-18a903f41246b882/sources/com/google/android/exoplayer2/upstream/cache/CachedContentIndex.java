package com.google.android.exoplayer2.upstream.cache;

import android.util.SparseArray;
import android.util.SparseBooleanArray;
import com.google.android.exoplayer2.upstream.cache.Cache;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.AtomicFile;
import com.google.android.exoplayer2.util.ReusableBufferedOutputStream;
import com.google.android.exoplayer2.util.Util;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Random;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* JADX INFO: loaded from: classes2.dex */
class CachedContentIndex {
    public static final String FILE_NAME = "cached_content_index.exi";
    private static final int FLAG_ENCRYPTED_INDEX = 1;
    private static final int VERSION = 2;
    private final AtomicFile atomicFile;
    private ReusableBufferedOutputStream bufferedOutputStream;
    private boolean changed;
    private final Cipher cipher;
    private final boolean encrypt;
    private final SparseArray<String> idToKey;
    private final HashMap<String, CachedContent> keyToContent;
    private final SparseBooleanArray removedIds;
    private final SecretKeySpec secretKeySpec;

    public CachedContentIndex(File cacheDir) {
        this(cacheDir, null);
    }

    public CachedContentIndex(File cacheDir, byte[] secretKey) {
        this(cacheDir, secretKey, secretKey != null);
    }

    public CachedContentIndex(File cacheDir, byte[] secretKey, boolean encrypt) {
        this.encrypt = encrypt;
        if (secretKey != null) {
            Assertions.checkArgument(secretKey.length == 16);
            try {
                this.cipher = getCipher();
                this.secretKeySpec = new SecretKeySpec(secretKey, "AES");
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new IllegalStateException(e);
            }
        } else {
            Assertions.checkState(!encrypt);
            this.cipher = null;
            this.secretKeySpec = null;
        }
        this.keyToContent = new HashMap<>();
        this.idToKey = new SparseArray<>();
        this.removedIds = new SparseBooleanArray();
        this.atomicFile = new AtomicFile(new File(cacheDir, FILE_NAME));
    }

    public void load() {
        Assertions.checkState(!this.changed);
        if (!readFile()) {
            this.atomicFile.delete();
            this.keyToContent.clear();
            this.idToKey.clear();
        }
    }

    public void store() throws Cache.CacheException {
        if (!this.changed) {
            return;
        }
        writeFile();
        this.changed = false;
        int removedIdCount = this.removedIds.size();
        for (int i = 0; i < removedIdCount; i++) {
            this.idToKey.remove(this.removedIds.keyAt(i));
        }
        this.removedIds.clear();
    }

    public CachedContent getOrAdd(String key) {
        CachedContent cachedContent = this.keyToContent.get(key);
        return cachedContent == null ? addNew(key) : cachedContent;
    }

    public CachedContent get(String key) {
        return this.keyToContent.get(key);
    }

    public Collection<CachedContent> getAll() {
        return this.keyToContent.values();
    }

    public int assignIdForKey(String key) {
        return getOrAdd(key).id;
    }

    public String getKeyForId(int id) {
        return this.idToKey.get(id);
    }

    public void maybeRemove(String key) {
        CachedContent cachedContent = this.keyToContent.get(key);
        if (cachedContent != null && cachedContent.isEmpty() && !cachedContent.isLocked()) {
            this.keyToContent.remove(key);
            this.changed = true;
            this.idToKey.put(cachedContent.id, null);
            this.removedIds.put(cachedContent.id, true);
        }
    }

    public void removeEmpty() {
        String[] keys = new String[this.keyToContent.size()];
        this.keyToContent.keySet().toArray(keys);
        for (String key : keys) {
            maybeRemove(key);
        }
    }

    public Set<String> getKeys() {
        return this.keyToContent.keySet();
    }

    public void applyContentMetadataMutations(String key, ContentMetadataMutations mutations) {
        CachedContent cachedContent = getOrAdd(key);
        if (cachedContent.applyMetadataMutations(mutations)) {
            this.changed = true;
        }
    }

    public ContentMetadata getContentMetadata(String key) {
        CachedContent cachedContent = get(key);
        return cachedContent != null ? cachedContent.getMetadata() : DefaultContentMetadata.EMPTY;
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x006a A[Catch: all -> 0x009d, IOException -> 0x00a4, LOOP:0: B:28:0x0068->B:29:0x006a, LOOP_END, TryCatch #3 {IOException -> 0x00a4, all -> 0x009d, blocks: (B:3:0x0002, B:8:0x001e, B:10:0x0027, B:15:0x0033, B:16:0x003d, B:17:0x0045, B:27:0x0062, B:29:0x006a, B:30:0x0079, B:22:0x0056, B:23:0x005b, B:24:0x005c, B:26:0x0060), top: B:54:0x0002 }] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0086  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean readFile() {
        /*
            r11 = this;
            r0 = 0
            r1 = 0
            java.io.BufferedInputStream r2 = new java.io.BufferedInputStream     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            com.google.android.exoplayer2.util.AtomicFile r3 = r11.atomicFile     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            java.io.InputStream r3 = r3.openRead()     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            r2.<init>(r3)     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            java.io.DataInputStream r3 = new java.io.DataInputStream     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            r3.<init>(r2)     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            r0 = r3
            int r3 = r0.readInt()     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            if (r3 < 0) goto L97
            r4 = 2
            if (r3 <= r4) goto L1e
            goto L97
        L1e:
            int r5 = r0.readInt()     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            r6 = r5 & 1
            r7 = 1
            if (r6 == 0) goto L5c
            javax.crypto.Cipher r6 = r11.cipher     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            if (r6 != 0) goto L31
        L2d:
            com.google.android.exoplayer2.util.Util.closeQuietly(r0)
            return r1
        L31:
            r6 = 16
            byte[] r6 = new byte[r6]     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            r0.readFully(r6)     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            javax.crypto.spec.IvParameterSpec r8 = new javax.crypto.spec.IvParameterSpec     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            r8.<init>(r6)     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            javax.crypto.Cipher r9 = r11.cipher     // Catch: java.security.InvalidAlgorithmParameterException -> L53 java.security.InvalidKeyException -> L55 java.lang.Throwable -> L9d java.io.IOException -> La4
            javax.crypto.spec.SecretKeySpec r10 = r11.secretKeySpec     // Catch: java.security.InvalidAlgorithmParameterException -> L53 java.security.InvalidKeyException -> L55 java.lang.Throwable -> L9d java.io.IOException -> La4
            r9.init(r4, r10, r8)     // Catch: java.security.InvalidAlgorithmParameterException -> L53 java.security.InvalidKeyException -> L55 java.lang.Throwable -> L9d java.io.IOException -> La4
            java.io.DataInputStream r4 = new java.io.DataInputStream     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            javax.crypto.CipherInputStream r9 = new javax.crypto.CipherInputStream     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            javax.crypto.Cipher r10 = r11.cipher     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            r9.<init>(r2, r10)     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            r4.<init>(r9)     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            r0 = r4
        L52:
            goto L62
        L53:
            r4 = move-exception
            goto L56
        L55:
            r4 = move-exception
        L56:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            r7.<init>(r4)     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            throw r7     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
        L5c:
            boolean r4 = r11.encrypt     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            if (r4 == 0) goto L52
            r11.changed = r7     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
        L62:
            int r4 = r0.readInt()     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            r6 = 0
            r8 = 0
        L68:
            if (r8 >= r4) goto L79
            com.google.android.exoplayer2.upstream.cache.CachedContent r9 = com.google.android.exoplayer2.upstream.cache.CachedContent.readFromStream(r3, r0)     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            r11.add(r9)     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            int r10 = r9.headerHashCode(r3)     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            int r6 = r6 + r10
            int r8 = r8 + 1
            goto L68
        L79:
            int r8 = r0.readInt()     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            int r9 = r0.read()     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La4
            r10 = -1
            if (r9 != r10) goto L86
            r9 = 1
            goto L87
        L86:
            r9 = 0
        L87:
            if (r8 != r6) goto L91
            if (r9 != 0) goto L8c
            goto L91
        L8c:
            com.google.android.exoplayer2.util.Util.closeQuietly(r0)
            return r7
        L91:
            com.google.android.exoplayer2.util.Util.closeQuietly(r0)
            return r1
        L97:
            com.google.android.exoplayer2.util.Util.closeQuietly(r0)
            return r1
        L9d:
            r1 = move-exception
            if (r0 == 0) goto La3
            com.google.android.exoplayer2.util.Util.closeQuietly(r0)
        La3:
            throw r1
        La4:
            r2 = move-exception
            if (r0 == 0) goto Lab
            com.google.android.exoplayer2.util.Util.closeQuietly(r0)
        Lab:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.upstream.cache.CachedContentIndex.readFile():boolean");
    }

    private void writeFile() throws Cache.CacheException {
        DataOutputStream output = null;
        try {
            try {
                OutputStream outputStream = this.atomicFile.startWrite();
                if (this.bufferedOutputStream == null) {
                    this.bufferedOutputStream = new ReusableBufferedOutputStream(outputStream);
                } else {
                    this.bufferedOutputStream.reset(outputStream);
                }
                DataOutputStream output2 = new DataOutputStream(this.bufferedOutputStream);
                output2.writeInt(2);
                int flags = this.encrypt ? 1 : 0;
                output2.writeInt(flags);
                if (this.encrypt) {
                    byte[] initializationVector = new byte[16];
                    new Random().nextBytes(initializationVector);
                    output2.write(initializationVector);
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
                    try {
                        this.cipher.init(1, this.secretKeySpec, ivParameterSpec);
                        output2.flush();
                        output2 = new DataOutputStream(new CipherOutputStream(this.bufferedOutputStream, this.cipher));
                    } catch (InvalidAlgorithmParameterException e) {
                        e = e;
                        throw new IllegalStateException(e);
                    } catch (InvalidKeyException e2) {
                        e = e2;
                        throw new IllegalStateException(e);
                    }
                }
                output2.writeInt(this.keyToContent.size());
                int hashCode = 0;
                for (CachedContent cachedContent : this.keyToContent.values()) {
                    cachedContent.writeToStream(output2);
                    hashCode += cachedContent.headerHashCode(2);
                }
                output2.writeInt(hashCode);
                this.atomicFile.endWrite(output2);
                output = null;
            } catch (IOException e3) {
                throw new Cache.CacheException(e3);
            }
        } finally {
            Util.closeQuietly(output);
        }
    }

    private CachedContent addNew(String key) {
        int id = getNewId(this.idToKey);
        CachedContent cachedContent = new CachedContent(id, key);
        add(cachedContent);
        this.changed = true;
        return cachedContent;
    }

    private void add(CachedContent cachedContent) {
        this.keyToContent.put(cachedContent.key, cachedContent);
        this.idToKey.put(cachedContent.id, cachedContent.key);
    }

    private static Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        if (Util.SDK_INT == 18) {
            try {
                return Cipher.getInstance("AES/CBC/PKCS5PADDING", "BC");
            } catch (Throwable th) {
            }
        }
        return Cipher.getInstance("AES/CBC/PKCS5PADDING");
    }

    public static int getNewId(SparseArray<String> idToKey) {
        int size = idToKey.size();
        int id = size == 0 ? 0 : idToKey.keyAt(size - 1) + 1;
        if (id < 0) {
            id = 0;
            while (id < size && id == idToKey.keyAt(id)) {
                id++;
            }
        }
        return id;
    }
}
