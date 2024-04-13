if status is-interactive
    # Commands to run in interactive sessions can go here
end

function ssh --wraps ssh
    if test $TERM = xterm-kitty
        command kitty +kitten ssh $argv
    else
        command ssh $argv
    end
end

direnv hook fish | source
