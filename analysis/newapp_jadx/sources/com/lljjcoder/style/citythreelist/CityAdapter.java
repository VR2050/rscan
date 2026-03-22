package com.lljjcoder.style.citythreelist;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.recyclerview.widget.RecyclerView;
import com.lljjcoder.style.citylist.bean.CityInfoBean;
import com.lljjcoder.style.citypickerview.C3949R;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class CityAdapter extends RecyclerView.Adapter<MyViewHolder> {
    public List<CityInfoBean> cityList;
    public Context context;
    private OnItemSelectedListener mOnItemClickListener;

    public class MyViewHolder extends RecyclerView.ViewHolder {

        /* renamed from: tv */
        public TextView f10202tv;

        public MyViewHolder(View view) {
            super(view);
            this.f10202tv = (TextView) view.findViewById(C3949R.id.default_item_city_name_tv);
        }
    }

    public interface OnItemSelectedListener {
        void onItemSelected(View view, int i2);
    }

    public CityAdapter(Context context, List<CityInfoBean> list) {
        this.cityList = new ArrayList();
        this.cityList = list;
        this.context = context;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return this.cityList.size();
    }

    public void setOnItemClickListener(OnItemSelectedListener onItemSelectedListener) {
        this.mOnItemClickListener = onItemSelectedListener;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(MyViewHolder myViewHolder, final int i2) {
        myViewHolder.f10202tv.setText(this.cityList.get(i2).getName());
        myViewHolder.f10202tv.setOnClickListener(new View.OnClickListener() { // from class: com.lljjcoder.style.citythreelist.CityAdapter.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (CityAdapter.this.mOnItemClickListener == null || i2 >= CityAdapter.this.cityList.size()) {
                    return;
                }
                CityAdapter.this.mOnItemClickListener.onItemSelected(view, i2);
            }
        });
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public MyViewHolder onCreateViewHolder(ViewGroup viewGroup, int i2) {
        return new MyViewHolder(LayoutInflater.from(this.context).inflate(C3949R.layout.item_citylist, viewGroup, false));
    }
}
