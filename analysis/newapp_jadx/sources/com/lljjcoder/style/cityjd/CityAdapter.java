package com.lljjcoder.style.cityjd;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import com.lljjcoder.bean.CityBean;
import com.lljjcoder.style.citypickerview.C3949R;
import java.util.List;

/* loaded from: classes2.dex */
public class CityAdapter extends BaseAdapter {
    private int cityIndex = -1;
    public Context context;
    public List<CityBean> mCityList;

    public class Holder {
        public TextView name;
        public ImageView selectImg;

        public Holder() {
        }
    }

    public CityAdapter(Context context, List<CityBean> list) {
        this.context = context;
        this.mCityList = list;
    }

    @Override // android.widget.Adapter
    public int getCount() {
        return this.mCityList.size();
    }

    @Override // android.widget.Adapter
    public long getItemId(int i2) {
        return Long.parseLong(this.mCityList.get(i2).getId());
    }

    public int getSelectedPosition() {
        return this.cityIndex;
    }

    @Override // android.widget.Adapter
    public View getView(int i2, View view, ViewGroup viewGroup) {
        Holder holder;
        if (view == null) {
            view = LayoutInflater.from(viewGroup.getContext()).inflate(C3949R.layout.pop_jdcitypicker_item, viewGroup, false);
            holder = new Holder();
            holder.name = (TextView) view.findViewById(C3949R.id.name);
            holder.selectImg = (ImageView) view.findViewById(C3949R.id.selectImg);
            view.setTag(holder);
        } else {
            holder = (Holder) view.getTag();
        }
        CityBean item = getItem(i2);
        holder.name.setText(item.getName());
        int i3 = this.cityIndex;
        boolean z = i3 != -1 && this.mCityList.get(i3).getName().equals(item.getName());
        holder.name.setEnabled(!z);
        holder.selectImg.setVisibility(z ? 0 : 8);
        return view;
    }

    public void updateSelectedPosition(int i2) {
        this.cityIndex = i2;
    }

    @Override // android.widget.Adapter
    public CityBean getItem(int i2) {
        return this.mCityList.get(i2);
    }
}
