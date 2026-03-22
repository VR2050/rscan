package com.luck.picture.lib;

import android.content.Context;
import android.content.ContextWrapper;
import com.luck.picture.lib.language.PictureLanguageUtils;

/* loaded from: classes2.dex */
public class PictureContextWrapper extends ContextWrapper {
    public PictureContextWrapper(Context context) {
        super(context);
    }

    public static ContextWrapper wrap(Context context, int i2) {
        PictureLanguageUtils.setAppLanguage(context, i2);
        return new PictureContextWrapper(context);
    }
}
