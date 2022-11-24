﻿using PKISharp.WACS.Plugins.Interfaces;
using PKISharp.WACS.Services;
using PKISharp.WACS.Services.Serialization;
using System;
using System.Diagnostics.CodeAnalysis;

namespace PKISharp.WACS.Plugins.Base.Options
{
    public class OrderPluginOptions : PluginOptions
    {
        public override string Name => throw new NotImplementedException();
        public override string Description => throw new NotImplementedException();
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
        public override Type Instance => throw new NotImplementedException();
    }

    public abstract class OrderPluginOptions<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] T> : 
        OrderPluginOptions where T : IOrderPlugin
    {
        public abstract override string Name { get; }
        public abstract override string Description { get; }

        public override void Show(IInputService input)
        {
            input.Show(null, "[Order]");
            input.Show("Plugin", $"{Name} - ({Description})", level: 1);
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
        public override Type Instance => typeof(T);
    }
}
