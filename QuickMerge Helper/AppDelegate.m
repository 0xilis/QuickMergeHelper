//
//  AppDelegate.m
//  QuickMerge Helper
//
//  Created by Snoolie Keffaber on 2024/03/13.
//

#import "AppDelegate.h"
#import "HomeViewController.h"

UINavigationController *navigationController;

@interface AppDelegate ()

@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    /* inline asm can reduce a good bit of instructions here */
    UIWindow *window = [[UIWindow alloc]initWithFrame:[[UIScreen mainScreen]bounds]];
    _window = window;
    [window makeKeyAndVisible];
    window.backgroundColor = [UIColor systemBackgroundColor];
    UINavigationController* navBar = [[UINavigationController alloc]initWithRootViewController:[[HomeViewController alloc]init]];
    [window setRootViewController:navBar];
    navigationController = navBar;
    return YES;
}

-(BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenURLOptionsKey,id> *)options {
    /* inline asm can reduce a good bit of instructions here */
    UIWindow *window = [[UIWindow alloc]initWithFrame:[[UIScreen mainScreen]bounds]];
    _window = window;
    [window makeKeyAndVisible];
    window.backgroundColor = [UIColor systemBackgroundColor];
    UINavigationController* navBar = [[UINavigationController alloc]initWithRootViewController:[[HomeViewController alloc]init]];
    [window setRootViewController:navBar];
    navigationController = navBar;
    return YES;
}

@end
