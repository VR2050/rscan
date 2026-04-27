package com.fm.openinstall.listener;

import com.fm.openinstall.model.AppData;
import com.fm.openinstall.model.Error;

/* JADX INFO: loaded from: classes.dex */
public interface AppWakeUpListener {
    void onWakeUpFinish(AppData appData, Error error);
}
