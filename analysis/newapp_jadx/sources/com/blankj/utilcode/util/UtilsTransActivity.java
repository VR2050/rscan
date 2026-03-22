package com.blankj.utilcode.util;

import android.content.Intent;
import android.os.Bundle;
import android.view.MotionEvent;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/* loaded from: classes.dex */
public class UtilsTransActivity extends AppCompatActivity {

    /* renamed from: c */
    public static final Map<UtilsTransActivity, AbstractC3220a> f8840c = new HashMap();

    /* renamed from: com.blankj.utilcode.util.UtilsTransActivity$a */
    public static abstract class AbstractC3220a implements Serializable {
        /* renamed from: a */
        public boolean mo703a(@NonNull UtilsTransActivity utilsTransActivity, MotionEvent motionEvent) {
            return false;
        }

        /* renamed from: b */
        public void mo704b(@NonNull UtilsTransActivity utilsTransActivity, int i2, int i3, Intent intent) {
        }

        /* renamed from: c */
        public void mo705c(@NonNull UtilsTransActivity utilsTransActivity, @Nullable Bundle bundle) {
        }

        /* renamed from: d */
        public void mo706d(@NonNull UtilsTransActivity utilsTransActivity) {
        }

        /* renamed from: e */
        public void mo707e(@NonNull UtilsTransActivity utilsTransActivity, int i2, @NonNull String[] strArr, @NonNull int[] iArr) {
        }
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean dispatchTouchEvent(MotionEvent motionEvent) {
        AbstractC3220a abstractC3220a = f8840c.get(this);
        if (abstractC3220a == null) {
            return super.dispatchTouchEvent(motionEvent);
        }
        if (abstractC3220a.mo703a(this, motionEvent)) {
            return true;
        }
        return super.dispatchTouchEvent(motionEvent);
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onActivityResult(int i2, int i3, Intent intent) {
        super.onActivityResult(i2, i3, intent);
        AbstractC3220a abstractC3220a = f8840c.get(this);
        if (abstractC3220a == null) {
            return;
        }
        abstractC3220a.mo704b(this, i2, i3, intent);
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle bundle) {
        overridePendingTransition(0, 0);
        Serializable serializableExtra = getIntent().getSerializableExtra("extra_delegate");
        if (!(serializableExtra instanceof AbstractC3220a)) {
            super.onCreate(bundle);
            finish();
            return;
        }
        AbstractC3220a abstractC3220a = (AbstractC3220a) serializableExtra;
        f8840c.put(this, abstractC3220a);
        Objects.requireNonNull(abstractC3220a);
        super.onCreate(bundle);
        abstractC3220a.mo705c(this, bundle);
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        Map<UtilsTransActivity, AbstractC3220a> map = f8840c;
        AbstractC3220a abstractC3220a = map.get(this);
        if (abstractC3220a == null) {
            return;
        }
        abstractC3220a.mo706d(this);
        map.remove(this);
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onPause() {
        overridePendingTransition(0, 0);
        super.onPause();
        if (f8840c.get(this) == null) {
        }
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onRequestPermissionsResult(int i2, @NonNull String[] strArr, @NonNull int[] iArr) {
        super.onRequestPermissionsResult(i2, strArr, iArr);
        AbstractC3220a abstractC3220a = f8840c.get(this);
        if (abstractC3220a == null) {
            return;
        }
        abstractC3220a.mo707e(this, i2, strArr, iArr);
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        super.onResume();
        if (f8840c.get(this) == null) {
        }
    }

    @Override // androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onSaveInstanceState(Bundle bundle) {
        super.onSaveInstanceState(bundle);
        if (f8840c.get(this) == null) {
        }
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onStart() {
        super.onStart();
        if (f8840c.get(this) == null) {
        }
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onStop() {
        super.onStop();
        if (f8840c.get(this) == null) {
        }
    }
}
