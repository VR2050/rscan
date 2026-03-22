package p005b.p190k.p197c.p198a;

import android.content.Context;
import android.graphics.Bitmap;
import android.renderscript.RSRuntimeException;
import androidx.renderscript.Allocation;
import androidx.renderscript.Element;
import androidx.renderscript.RenderScript;
import androidx.renderscript.ScriptIntrinsicBlur;

/* renamed from: b.k.c.a.b */
/* loaded from: classes.dex */
public class C1901b implements InterfaceC1902c {

    /* renamed from: a */
    public static Boolean f3003a;

    /* renamed from: b */
    public RenderScript f3004b;

    /* renamed from: c */
    public ScriptIntrinsicBlur f3005c;

    /* renamed from: d */
    public Allocation f3006d;

    /* renamed from: e */
    public Allocation f3007e;

    @Override // p005b.p190k.p197c.p198a.InterfaceC1902c
    /* renamed from: a */
    public void mo1251a(Bitmap bitmap, Bitmap bitmap2) {
        this.f3006d.copyFrom(bitmap);
        this.f3005c.setInput(this.f3006d);
        this.f3005c.forEach(this.f3007e);
        this.f3007e.copyTo(bitmap2);
    }

    @Override // p005b.p190k.p197c.p198a.InterfaceC1902c
    /* renamed from: b */
    public boolean mo1252b(Context context, Bitmap bitmap, float f2) {
        if (this.f3004b == null) {
            try {
                RenderScript create = RenderScript.create(context);
                this.f3004b = create;
                this.f3005c = ScriptIntrinsicBlur.create(create, Element.U8_4(create));
            } catch (RSRuntimeException e2) {
                if (f3003a == null && context != null) {
                    f3003a = Boolean.valueOf((context.getApplicationInfo().flags & 2) != 0);
                }
                if (f3003a == Boolean.TRUE) {
                    throw e2;
                }
                release();
                return false;
            }
        }
        this.f3005c.setRadius(f2);
        Allocation createFromBitmap = Allocation.createFromBitmap(this.f3004b, bitmap, Allocation.MipmapControl.MIPMAP_NONE, 1);
        this.f3006d = createFromBitmap;
        this.f3007e = Allocation.createTyped(this.f3004b, createFromBitmap.getType());
        return true;
    }

    @Override // p005b.p190k.p197c.p198a.InterfaceC1902c
    public void release() {
        Allocation allocation = this.f3006d;
        if (allocation != null) {
            allocation.destroy();
            this.f3006d = null;
        }
        Allocation allocation2 = this.f3007e;
        if (allocation2 != null) {
            allocation2.destroy();
            this.f3007e = null;
        }
        ScriptIntrinsicBlur scriptIntrinsicBlur = this.f3005c;
        if (scriptIntrinsicBlur != null) {
            scriptIntrinsicBlur.destroy();
            this.f3005c = null;
        }
        RenderScript renderScript = this.f3004b;
        if (renderScript != null) {
            renderScript.destroy();
            this.f3004b = null;
        }
    }
}
