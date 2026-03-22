package com.lljjcoder.style.cityjd;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import com.lljjcoder.bean.DistrictBean;
import com.lljjcoder.style.citypickerview.C3949R;
import java.util.List;

/* loaded from: classes2.dex */
public class AreaAdapter extends BaseAdapter {
    public Context context;
    private int districtIndex = -1;
    public List<DistrictBean> mDistrictList;

    public class Holder {
        public TextView name;
        public ImageView selectImg;

        public Holder() {
        }
    }

    public AreaAdapter(Context context, List<DistrictBean> list) {
        this.context = context;
        this.mDistrictList = list;
    }

    @Override // android.widget.Adapter
    public int getCount() {
        return this.mDistrictList.size();
    }

    @Override // android.widget.Adapter
    public long getItemId(int i2) {
        return Long.parseLong(this.mDistrictList.get(i2).getId());
    }

    public int getSelectedPosition() {
        return this.districtIndex;
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
        DistrictBean item = getItem(i2);
        holder.name.setText(item.getName());
        int i3 = this.districtIndex;
        boolean z = i3 != -1 && this.mDistrictList.get(i3).getName().equals(item.getName());
        holder.name.setEnabled(!z);
        holder.selectImg.setVisibility(z ? 0 : 8);
        return view;
    }

    public void updateSelectedPosition(int i2) {
        this.districtIndex = i2;
    }

    @Override // android.widget.Adapter
    public DistrictBean getItem(int i2) {
        return this.mDistrictList.get(i2);
    }
}
