package com.gyf.immersionbar;

/* loaded from: classes2.dex */
public class BarProperties {
    private int actionBarHeight;
    private boolean hasNavigationBar;
    private boolean landscapeLeft;
    private boolean landscapeRight;
    private int navigationBarHeight;
    private int navigationBarWidth;
    private int notchHeight;
    private boolean notchScreen;
    private boolean portrait;
    private int statusBarHeight;

    public int getActionBarHeight() {
        return this.actionBarHeight;
    }

    public int getNavigationBarHeight() {
        return this.navigationBarHeight;
    }

    public int getNavigationBarWidth() {
        return this.navigationBarWidth;
    }

    public int getNotchHeight() {
        return this.notchHeight;
    }

    public int getStatusBarHeight() {
        return this.statusBarHeight;
    }

    public boolean hasNavigationBar() {
        return this.hasNavigationBar;
    }

    public boolean isLandscapeLeft() {
        return this.landscapeLeft;
    }

    public boolean isLandscapeRight() {
        return this.landscapeRight;
    }

    public boolean isNotchScreen() {
        return this.notchScreen;
    }

    public boolean isPortrait() {
        return this.portrait;
    }

    public void setActionBarHeight(int i2) {
        this.actionBarHeight = i2;
    }

    public void setLandscapeLeft(boolean z) {
        this.landscapeLeft = z;
    }

    public void setLandscapeRight(boolean z) {
        this.landscapeRight = z;
    }

    public void setNavigationBar(boolean z) {
        this.hasNavigationBar = z;
    }

    public void setNavigationBarHeight(int i2) {
        this.navigationBarHeight = i2;
    }

    public void setNavigationBarWidth(int i2) {
        this.navigationBarWidth = i2;
    }

    public void setNotchHeight(int i2) {
        this.notchHeight = i2;
    }

    public void setNotchScreen(boolean z) {
        this.notchScreen = z;
    }

    public void setPortrait(boolean z) {
        this.portrait = z;
    }

    public void setStatusBarHeight(int i2) {
        this.statusBarHeight = i2;
    }
}
