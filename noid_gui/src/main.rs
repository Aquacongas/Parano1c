// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

mod app;
mod app_icon;
mod backend;
mod model;
mod secret;
mod theme;
mod view;
mod widgets;

use iced::{window, Size};

fn app_theme(_: &app::App) -> iced::Theme {
    theme::paranoid_theme()
}

fn main() -> iced::Result {
    iced::application(app::App::new, app::App::update, app::App::view)
        .title("ParanO(1)d")
        .theme(app_theme)
        .subscription(app::App::subscription)
        .font(include_bytes!("../assets/fonts/NotoSansMono-Regular.ttf").as_slice())
        .font(include_bytes!("../assets/fonts/NotoSans-Bold.ttf").as_slice())
        .font(include_bytes!("../assets/fonts/NotoSansSymbols-Bold.ttf").as_slice())
        .default_font(theme::TECH_FONT)
        .window(window::Settings {
            size: Size::new(1200.0, 760.0),
            min_size: Some(Size::new(920.0, 640.0)),
            position: window::Position::Centered,
            icon: Some(app_icon::icon()),
            ..window::Settings::default()
        })
        .exit_on_close_request(false)
        .antialiasing(true)
        .run()
}
