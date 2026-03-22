package p005b.p190k.p197c.p198a;

import android.content.Context;
import android.graphics.Bitmap;
import android.renderscript.RSRuntimeException;
import androidx.renderscript.Allocation;
import androidx.renderscript.Element;
import androidx.renderscript.RenderScript;
import androidx.renderscript.ScriptIntrinsicBlur;

/* renamed from: b.k.c.a.e */
/* loaded from: classes.dex */
public class C1904e implements InterfaceC1902c {

    /* renamed from: a */
    public static Boolean f3008a;

    /* renamed from: b */
    public RenderScript f3009b;

    /* renamed from: c */
    public ScriptIntrinsicBlur f3010c;

    /* renamed from: d */
    public Allocation f3011d;

    /* renamed from: e */
    public Allocation f3012e;

    @Override // p005b.p190k.p197c.p198a.InterfaceC1902c
    /* renamed from: a */
    public void mo1251a(Bitmap bitmap, Bitmap bitmap2) {
        this.f3011d.copyFrom(bitmap);
        this.f3010c.setInput(this.f3011d);
        this.f3010c.forEach(this.f3012e);
        this.f3012e.copyTo(bitmap2);
    }

    @Override // p005b.p190k.p197c.p198a.InterfaceC1902c
    /* renamed from: b */
    public boolean mo1252b(Context context, Bitmap bitmap, float f2) {
        if (this.f3009b == null) {
            try {
                RenderScript create = RenderScript.create(context);
                this.f3009b = create;
                this.f3010c = ScriptIntrinsicBlur.create(create, Element.U8_4(create));
            } catch (RSRuntimeException e2) {
                if (f3008a == null && context != null) {
                    f3008a = Boolean.valueOf((context.getApplicationInfo().flags & 2) != 0);
                }
                if (f3008a == Boolean.TRUE) {
                    throw e2;
                }
                release();
                return false;
            }
        }
        this.f3010c.setRadius(f2);
        Allocation createFromBitmap = Allocation.createFromBitmap(this.f3009b, bitmap, Allocation.MipmapControl.MIPMAP_NONE, 1);
        this.f3011d = createFromBitmap;
        this.f3012e = Allocation.createTyped(this.f3009b, createFromBitmap.getType());
        return true;
    }

    @Override // p005b.p190k.p197c.p198a.InterfaceC1902c
    public void release() {
        Allocation allocation = this.f3011d;
        if (allocation != null) {
            allocation.destroy();
            this.f3011d = null;
        }
        Allocation allocation2 = this.f3012e;
        if (allocation2 != null) {
            allocation2.destroy();
            this.f3012e = null;
        }
        ScriptIntrinsicBlur scriptIntrinsicBlur = this.f3010c;
        if (scriptIntrinsicBlur != null) {
            scriptIntrinsicBlur.destroy();
            this.f3010c = null;
        }
        RenderScript renderScript = this.f3009b;
        if (renderScript != null) {
            renderScript.destroy();
            this.f3009b = null;
        }
    }
}
