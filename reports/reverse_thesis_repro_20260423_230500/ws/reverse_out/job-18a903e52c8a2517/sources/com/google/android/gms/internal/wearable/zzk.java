package com.google.android.gms.internal.wearable;

import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import java.io.IOException;
import kotlin.UByte;
import kotlin.jvm.internal.ByteCompanionObject;

/* JADX INFO: loaded from: classes.dex */
public final class zzk {
    private final byte[] buffer;
    private final int zzgr;
    private final int zzgs;
    private int zzgt;
    private int zzgu;
    private int zzgv;
    private int zzgw;
    private int zzgy;
    private int zzgx = Integer.MAX_VALUE;
    private int zzgz = 64;
    private int zzha = ConnectionsManager.FileTypeFile;

    public static zzk zza(byte[] bArr, int i, int i2) {
        return new zzk(bArr, 0, i2);
    }

    public final int zzj() throws IOException {
        if (this.zzgv == this.zzgt) {
            this.zzgw = 0;
            return 0;
        }
        int iZzk = zzk();
        this.zzgw = iZzk;
        if (iZzk != 0) {
            return iZzk;
        }
        throw new zzs("Protocol message contained an invalid tag (zero).");
    }

    public final void zzc(int i) throws zzs {
        if (this.zzgw != i) {
            throw new zzs("Protocol message end-group tag did not match expected tag.");
        }
    }

    public final boolean zzd(int i) throws IOException {
        int iZzj;
        int i2 = i & 7;
        if (i2 != 0) {
            if (i2 == 1) {
                zzn();
                return true;
            }
            if (i2 == 2) {
                zzh(zzk());
                return true;
            }
            if (i2 != 3) {
                if (i2 == 4) {
                    return false;
                }
                if (i2 == 5) {
                    zzm();
                    return true;
                }
                throw new zzs("Protocol message tag had invalid wire type.");
            }
            do {
                iZzj = zzj();
                if (iZzj == 0) {
                    break;
                }
            } while (zzd(iZzj));
            zzc(((i >>> 3) << 3) | 4);
            return true;
        }
        zzk();
        return true;
    }

    public final String readString() throws IOException {
        int iZzk = zzk();
        if (iZzk < 0) {
            throw zzs.zzv();
        }
        if (iZzk > this.zzgt - this.zzgv) {
            throw zzs.zzu();
        }
        String str = new String(this.buffer, this.zzgv, iZzk, zzr.UTF_8);
        this.zzgv += iZzk;
        return str;
    }

    public final void zza(zzt zztVar) throws IOException {
        int iZzk = zzk();
        if (this.zzgy >= this.zzgz) {
            throw new zzs("Protocol message had too many levels of nesting.  May be malicious.  Use CodedInputStream.setRecursionLimit() to increase the depth limit.");
        }
        int iZze = zze(iZzk);
        this.zzgy++;
        zztVar.zza(this);
        zzc(0);
        this.zzgy--;
        zzf(iZze);
    }

    public final byte[] readBytes() throws IOException {
        int iZzk = zzk();
        if (iZzk < 0) {
            throw zzs.zzv();
        }
        if (iZzk == 0) {
            return zzw.zzhy;
        }
        int i = this.zzgt;
        int i2 = this.zzgv;
        if (iZzk > i - i2) {
            throw zzs.zzu();
        }
        byte[] bArr = new byte[iZzk];
        System.arraycopy(this.buffer, i2, bArr, 0, iZzk);
        this.zzgv += iZzk;
        return bArr;
    }

    public final int zzk() throws IOException {
        byte bZzq = zzq();
        if (bZzq >= 0) {
            return bZzq;
        }
        int i = bZzq & ByteCompanionObject.MAX_VALUE;
        byte bZzq2 = zzq();
        if (bZzq2 >= 0) {
            return i | (bZzq2 << 7);
        }
        int i2 = i | ((bZzq2 & ByteCompanionObject.MAX_VALUE) << 7);
        byte bZzq3 = zzq();
        if (bZzq3 >= 0) {
            return i2 | (bZzq3 << 14);
        }
        int i3 = i2 | ((bZzq3 & ByteCompanionObject.MAX_VALUE) << 14);
        byte bZzq4 = zzq();
        if (bZzq4 >= 0) {
            return i3 | (bZzq4 << 21);
        }
        int i4 = i3 | ((bZzq4 & ByteCompanionObject.MAX_VALUE) << 21);
        byte bZzq5 = zzq();
        int i5 = i4 | (bZzq5 << 28);
        if (bZzq5 < 0) {
            for (int i6 = 0; i6 < 5; i6++) {
                if (zzq() >= 0) {
                    return i5;
                }
            }
            throw zzs.zzw();
        }
        return i5;
    }

    public final long zzl() throws IOException {
        long j = 0;
        for (int i = 0; i < 64; i += 7) {
            byte bZzq = zzq();
            j |= ((long) (bZzq & ByteCompanionObject.MAX_VALUE)) << i;
            if ((bZzq & ByteCompanionObject.MIN_VALUE) == 0) {
                return j;
            }
        }
        throw zzs.zzw();
    }

    public final int zzm() throws IOException {
        return (zzq() & UByte.MAX_VALUE) | ((zzq() & UByte.MAX_VALUE) << 8) | ((zzq() & UByte.MAX_VALUE) << 16) | ((zzq() & UByte.MAX_VALUE) << 24);
    }

    public final long zzn() throws IOException {
        byte bZzq = zzq();
        return ((((long) zzq()) & 255) << 8) | (((long) bZzq) & 255) | ((((long) zzq()) & 255) << 16) | ((((long) zzq()) & 255) << 24) | ((((long) zzq()) & 255) << 32) | ((((long) zzq()) & 255) << 40) | ((((long) zzq()) & 255) << 48) | ((((long) zzq()) & 255) << 56);
    }

    private zzk(byte[] bArr, int i, int i2) {
        this.buffer = bArr;
        this.zzgr = i;
        int i3 = i2 + i;
        this.zzgt = i3;
        this.zzgs = i3;
        this.zzgv = i;
    }

    public final int zze(int i) throws zzs {
        if (i < 0) {
            throw zzs.zzv();
        }
        int i2 = i + this.zzgv;
        int i3 = this.zzgx;
        if (i2 > i3) {
            throw zzs.zzu();
        }
        this.zzgx = i2;
        zzo();
        return i3;
    }

    private final void zzo() {
        int i = this.zzgt + this.zzgu;
        this.zzgt = i;
        int i2 = this.zzgx;
        if (i > i2) {
            int i3 = i - i2;
            this.zzgu = i3;
            this.zzgt = i - i3;
            return;
        }
        this.zzgu = 0;
    }

    public final void zzf(int i) {
        this.zzgx = i;
        zzo();
    }

    public final int zzp() {
        int i = this.zzgx;
        if (i == Integer.MAX_VALUE) {
            return -1;
        }
        return i - this.zzgv;
    }

    public final int getPosition() {
        return this.zzgv - this.zzgr;
    }

    public final byte[] zzb(int i, int i2) {
        if (i2 == 0) {
            return zzw.zzhy;
        }
        byte[] bArr = new byte[i2];
        System.arraycopy(this.buffer, this.zzgr + i, bArr, 0, i2);
        return bArr;
    }

    public final void zzg(int i) {
        zzc(i, this.zzgw);
    }

    final void zzc(int i, int i2) {
        int i3 = this.zzgv;
        int i4 = this.zzgr;
        if (i > i3 - i4) {
            int i5 = this.zzgv - this.zzgr;
            StringBuilder sb = new StringBuilder(50);
            sb.append("Position ");
            sb.append(i);
            sb.append(" is beyond current ");
            sb.append(i5);
            throw new IllegalArgumentException(sb.toString());
        }
        if (i < 0) {
            StringBuilder sb2 = new StringBuilder(24);
            sb2.append("Bad position ");
            sb2.append(i);
            throw new IllegalArgumentException(sb2.toString());
        }
        this.zzgv = i4 + i;
        this.zzgw = i2;
    }

    private final byte zzq() throws IOException {
        int i = this.zzgv;
        if (i == this.zzgt) {
            throw zzs.zzu();
        }
        byte[] bArr = this.buffer;
        this.zzgv = i + 1;
        return bArr[i];
    }

    private final void zzh(int i) throws IOException {
        if (i < 0) {
            throw zzs.zzv();
        }
        int i2 = this.zzgv;
        int i3 = i2 + i;
        int i4 = this.zzgx;
        if (i3 > i4) {
            zzh(i4 - i2);
            throw zzs.zzu();
        }
        if (i <= this.zzgt - i2) {
            this.zzgv = i2 + i;
            return;
        }
        throw zzs.zzu();
    }
}
