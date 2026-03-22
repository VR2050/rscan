package p005b.p190k.p197c.p198a;

import android.annotation.TargetApi;
import android.content.Context;
import android.graphics.Bitmap;
import android.renderscript.Allocation;
import android.renderscript.Element;
import android.renderscript.RSRuntimeException;
import android.renderscript.RenderScript;
import android.renderscript.ScriptIntrinsicBlur;

@TargetApi(17)
/* renamed from: b.k.c.a.a */
/* loaded from: classes.dex */
public class C1900a implements InterfaceC1902c {

    /* renamed from: a */
    public static Boolean f2998a;

    /* renamed from: b */
    public RenderScript f2999b;

    /* renamed from: c */
    public ScriptIntrinsicBlur f3000c;

    /* renamed from: d */
    public Allocation f3001d;

    /* renamed from: e */
    public Allocation f3002e;

    @Override // p005b.p190k.p197c.p198a.InterfaceC1902c
    /* renamed from: a */
    public void mo1251a(Bitmap bitmap, Bitmap bitmap2) {
        this.f3001d.copyFrom(bitmap);
        this.f3000c.setInput(this.f3001d);
        this.f3000c.forEach(this.f3002e);
        this.f3002e.copyTo(bitmap2);
    }

    @Override // p005b.p190k.p197c.p198a.InterfaceC1902c
    /* renamed from: b */
    public boolean mo1252b(Context context, Bitmap bitmap, float f2) {
        if (this.f2999b == null) {
            try {
                RenderScript create = RenderScript.create(context);
                this.f2999b = create;
                this.f3000c = ScriptIntrinsicBlur.create(create, Element.U8_4(create));
            } catch (RSRuntimeException e2) {
                if (f2998a == null && context != null) {
                    f2998a = Boolean.valueOf((context.getApplicationInfo().flags & 2) != 0);
                }
                if (f2998a == Boolean.TRUE) {
                    throw e2;
                }
                release();
                return false;
            }
        }
        this.f3000c.setRadius(f2);
        Allocation createFromBitmap = Allocation.createFromBitmap(this.f2999b, bitmap, Allocation.MipmapControl.MIPMAP_NONE, 1);
        this.f3001d = createFromBitmap;
        this.f3002e = Allocation.createTyped(this.f2999b, createFromBitmap.getType());
        return true;
    }

    @Override // p005b.p190k.p197c.p198a.InterfaceC1902c
    public void release() {
        Allocation allocation = this.f3001d;
        if (allocation != null) {
            allocation.destroy();
            this.f3001d = null;
        }
        Allocation allocation2 = this.f3002e;
        if (allocation2 != null) {
            allocation2.destroy();
            this.f3002e = null;
        }
        ScriptIntrinsicBlur scriptIntrinsicBlur = this.f3000c;
        if (scriptIntrinsicBlur != null) {
            scriptIntrinsicBlur.destroy();
            this.f3000c = null;
        }
        RenderScript renderScript = this.f2999b;
        if (renderScript != null) {
            renderScript.destroy();
            this.f2999b = null;
        }
    }
}
