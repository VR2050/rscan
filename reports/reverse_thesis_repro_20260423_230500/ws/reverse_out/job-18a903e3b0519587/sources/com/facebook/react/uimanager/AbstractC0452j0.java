package com.facebook.react.uimanager;

import android.graphics.Rect;
import android.view.View;
import android.view.ViewParent;

/* JADX INFO: renamed from: com.facebook.react.uimanager.j0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0452j0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final Rect f7730a = new Rect();

    public static void a(View view, Rect rect) {
        ViewParent parent = view.getParent();
        if (parent == null) {
            rect.setEmpty();
            return;
        }
        if (parent instanceof InterfaceC0450i0) {
            InterfaceC0450i0 interfaceC0450i0 = (InterfaceC0450i0) parent;
            if (interfaceC0450i0.getRemoveClippedSubviews()) {
                Rect rect2 = f7730a;
                interfaceC0450i0.g(rect2);
                if (!rect2.intersect(view.getLeft(), view.getTop() + ((int) view.getTranslationY()), view.getRight(), view.getBottom() + ((int) view.getTranslationY()))) {
                    rect.setEmpty();
                    return;
                }
                rect2.offset(-view.getLeft(), -view.getTop());
                rect2.offset(-((int) view.getTranslationX()), -((int) view.getTranslationY()));
                rect2.offset(view.getScrollX(), view.getScrollY());
                rect.set(rect2);
                return;
            }
        }
        view.getDrawingRect(rect);
    }
}
