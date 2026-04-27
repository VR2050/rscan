package androidx.core.view;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.os.Build;
import android.util.Log;
import android.view.MenuItem;
import n.InterfaceMenuItemC0631b;

/* JADX INFO: renamed from: androidx.core.view.x, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0286x {

    /* JADX INFO: renamed from: androidx.core.view.x$a */
    static class a {
        static int a(MenuItem menuItem) {
            return menuItem.getAlphabeticModifiers();
        }

        static CharSequence b(MenuItem menuItem) {
            return menuItem.getContentDescription();
        }

        static ColorStateList c(MenuItem menuItem) {
            return menuItem.getIconTintList();
        }

        static PorterDuff.Mode d(MenuItem menuItem) {
            return menuItem.getIconTintMode();
        }

        static int e(MenuItem menuItem) {
            return menuItem.getNumericModifiers();
        }

        static CharSequence f(MenuItem menuItem) {
            return menuItem.getTooltipText();
        }

        static MenuItem g(MenuItem menuItem, char c3, int i3) {
            return menuItem.setAlphabeticShortcut(c3, i3);
        }

        static MenuItem h(MenuItem menuItem, CharSequence charSequence) {
            return menuItem.setContentDescription(charSequence);
        }

        static MenuItem i(MenuItem menuItem, ColorStateList colorStateList) {
            return menuItem.setIconTintList(colorStateList);
        }

        static MenuItem j(MenuItem menuItem, PorterDuff.Mode mode) {
            return menuItem.setIconTintMode(mode);
        }

        static MenuItem k(MenuItem menuItem, char c3, int i3) {
            return menuItem.setNumericShortcut(c3, i3);
        }

        static MenuItem l(MenuItem menuItem, char c3, char c4, int i3, int i4) {
            return menuItem.setShortcut(c3, c4, i3, i4);
        }

        static MenuItem m(MenuItem menuItem, CharSequence charSequence) {
            return menuItem.setTooltipText(charSequence);
        }
    }

    public static MenuItem a(MenuItem menuItem, AbstractC0254b abstractC0254b) {
        if (menuItem instanceof InterfaceMenuItemC0631b) {
            return ((InterfaceMenuItemC0631b) menuItem).a(abstractC0254b);
        }
        Log.w("MenuItemCompat", "setActionProvider: item does not implement SupportMenuItem; ignoring");
        return menuItem;
    }

    public static void b(MenuItem menuItem, char c3, int i3) {
        if (menuItem instanceof InterfaceMenuItemC0631b) {
            ((InterfaceMenuItemC0631b) menuItem).setAlphabeticShortcut(c3, i3);
        } else if (Build.VERSION.SDK_INT >= 26) {
            a.g(menuItem, c3, i3);
        }
    }

    public static void c(MenuItem menuItem, CharSequence charSequence) {
        if (menuItem instanceof InterfaceMenuItemC0631b) {
            ((InterfaceMenuItemC0631b) menuItem).setContentDescription(charSequence);
        } else if (Build.VERSION.SDK_INT >= 26) {
            a.h(menuItem, charSequence);
        }
    }

    public static void d(MenuItem menuItem, ColorStateList colorStateList) {
        if (menuItem instanceof InterfaceMenuItemC0631b) {
            ((InterfaceMenuItemC0631b) menuItem).setIconTintList(colorStateList);
        } else if (Build.VERSION.SDK_INT >= 26) {
            a.i(menuItem, colorStateList);
        }
    }

    public static void e(MenuItem menuItem, PorterDuff.Mode mode) {
        if (menuItem instanceof InterfaceMenuItemC0631b) {
            ((InterfaceMenuItemC0631b) menuItem).setIconTintMode(mode);
        } else if (Build.VERSION.SDK_INT >= 26) {
            a.j(menuItem, mode);
        }
    }

    public static void f(MenuItem menuItem, char c3, int i3) {
        if (menuItem instanceof InterfaceMenuItemC0631b) {
            ((InterfaceMenuItemC0631b) menuItem).setNumericShortcut(c3, i3);
        } else if (Build.VERSION.SDK_INT >= 26) {
            a.k(menuItem, c3, i3);
        }
    }

    public static void g(MenuItem menuItem, CharSequence charSequence) {
        if (menuItem instanceof InterfaceMenuItemC0631b) {
            ((InterfaceMenuItemC0631b) menuItem).setTooltipText(charSequence);
        } else if (Build.VERSION.SDK_INT >= 26) {
            a.m(menuItem, charSequence);
        }
    }
}
