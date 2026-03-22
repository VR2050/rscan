package com.blankj.utilcode.util;

import android.app.Application;
import androidx.core.content.FileProvider;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class UtilsFileProvider extends FileProvider {
    @Override // androidx.core.content.FileProvider, android.content.ContentProvider
    public boolean onCreate() {
        C4195m.m4827q0((Application) getContext().getApplicationContext());
        return true;
    }
}
