package com.glass.protector.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.glass.protector.R;

/**
 * 关于页面 - 内容占位，用户后续自行填写
 * 可修改以下字段内容：
 * - R.id.aboutDescription: 软件介绍
 * - R.id.aboutFeatures: 功能特性
 * - R.id.aboutContact: 联系方式
 */
public class AboutFragment extends Fragment {

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_about, container, false);
    }
}
