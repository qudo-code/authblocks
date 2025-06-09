<script lang="ts">
    import { page } from "$app/state";

    $effect(() => {
        console.log({page});
    });
</script>

<h1>Users</h1>
<ul class="flex flex-col gap-2">
    {#each page.data.users as user}
        <li class="flex items-center gap-2">
            <img src={user.avatar} alt={user.name} class="w-12 h-12 rounded-full"/>
            <span>{user.name}</span>
        </li>
    {/each}
</ul>