package com.lljjcoder.style.citypickerview.widget.wheel.adapters;

import android.database.DataSetObserver;
import android.view.View;
import android.view.ViewGroup;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/* loaded from: classes2.dex */
public abstract class AbstractWheelAdapter implements WheelViewAdapter {
    private List<DataSetObserver> datasetObservers;

    @Override // com.lljjcoder.style.citypickerview.widget.wheel.adapters.WheelViewAdapter
    public View getEmptyItem(View view, ViewGroup viewGroup) {
        return null;
    }

    public void notifyDataChangedEvent() {
        List<DataSetObserver> list = this.datasetObservers;
        if (list != null) {
            Iterator<DataSetObserver> it = list.iterator();
            while (it.hasNext()) {
                it.next().onChanged();
            }
        }
    }

    public void notifyDataInvalidatedEvent() {
        List<DataSetObserver> list = this.datasetObservers;
        if (list != null) {
            Iterator<DataSetObserver> it = list.iterator();
            while (it.hasNext()) {
                it.next().onInvalidated();
            }
        }
    }

    @Override // com.lljjcoder.style.citypickerview.widget.wheel.adapters.WheelViewAdapter
    public void registerDataSetObserver(DataSetObserver dataSetObserver) {
        if (this.datasetObservers == null) {
            this.datasetObservers = new LinkedList();
        }
        this.datasetObservers.add(dataSetObserver);
    }

    @Override // com.lljjcoder.style.citypickerview.widget.wheel.adapters.WheelViewAdapter
    public void unregisterDataSetObserver(DataSetObserver dataSetObserver) {
        List<DataSetObserver> list = this.datasetObservers;
        if (list != null) {
            list.remove(dataSetObserver);
        }
    }
}
